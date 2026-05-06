// SPDX-License-Identifier: GPL-2.0
//
// network.bpf.c — rastreia conexões TCP do PID alvo:
//
//   1. tracepoint sock:inet_sock_set_state → descobre 5-tuple + state
//   2. kprobe   tcp_sendmsg                → bytes Tx
//   3. kprobe   tcp_cleanup_rbuf           → bytes Rx
//
// Truque pra evitar dereferenciar `struct sock` (que exigiria vmlinux.h
// ou offsets manuais frágeis): o tracepoint inet_sock_set_state já entrega
// o `skaddr` (ponteiro kernel do sock) JUNTO com a 5-tuple, então mantemos
// um map auxiliar sock_to_key (skaddr → net_key). Os kprobes em
// tcp_sendmsg/cleanup_rbuf recebem o `struct sock *sk` no primeiro arg
// via PT_REGS_PARM1 — usam o ponteiro como chave do sock_to_key e
// acumulam bytes no net_val correspondente, sem ler nenhum campo do sock.
//
// Maps:
//   net_target_pid   ARRAY[1]  pid alvo (escrito pelo loader Go)
//   net_conn_map     HASH      net_key → net_val (state, RTT, tx/rx bytes)
//   sock_to_key      HASH      sock_ptr → net_key (correlação)
//
// Limitações:
//   - Conexões pré-existentes (abertas antes de xray attachar) não entram
//     no sock_to_key, então tx/rx ficam 0 pra elas. Conexões novas funcionam.
//   - bpf_get_current_pid_tgid() em softirq retorna a task interrompida —
//     pode pular ou contar errado em transições no path de softirq.
//     tcp_sendmsg/cleanup_rbuf rodam em process context, então OK.

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define AF_INET  2
#define AF_INET6 10

#define IPPROTO_TCP 6

#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT    2
#define TCP_CLOSE       7

// Layout do tracepoint sock:inet_sock_set_state — estável desde 4.16.
// kernel emite sport/dport já em host-order (ntohs), addrs em network order.
struct sock_set_state_args {
    unsigned long long _pad;
    const void *skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8  saddr[4];
    __u8  daddr[4];
    __u8  saddr_v6[16];
    __u8  daddr_v6[16];
};

// net_key: 5-tuple. Pra IPv4, os 4 primeiros bytes de saddr/daddr são
// significativos e o restante vai zero. Layout fixo (40 bytes) batendo
// com NetConnKey em internal/bpf/network.go.
struct net_key {
    __u8  daddr[16];
    __u8  saddr[16];
    __u16 dport;
    __u16 sport;
    __u16 family;
    __u16 _pad;
};

struct net_val {
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u64 syn_sent_ns;
    __u64 established_ns;
    __u64 rtt_ns;
    __u64 tx_bytes;
    __u64 rx_bytes;
    __u32 state;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} net_target_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct net_key);
    __type(value, struct net_val);
    __uint(max_entries, 4096);
} net_conn_map SEC(".maps");

// sock_to_key: ponteiro kernel do sock → 5-tuple, usado pra correlacionar
// kprobes (que recebem sk como arg) com o net_conn_map (keyed por 5-tuple).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct net_key);
    __uint(max_entries, 4096);
} sock_to_key SEC(".maps");

static __always_inline int is_net_target(void)
{
    __u32 key = 0;
    __u32 *target = bpf_map_lookup_elem(&net_target_pid, &key);
    if (!target || *target == 0)
        return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);
    return tgid == *target;
}

SEC("tracepoint/sock/inet_sock_set_state")
int handle_inet_set_state(struct sock_set_state_args *ctx)
{
    if (ctx->protocol != IPPROTO_TCP)
        return 0;
    if (!is_net_target())
        return 0;

    struct net_key k = {};
    k.family = ctx->family;
    k.sport  = ctx->sport;
    k.dport  = ctx->dport;
    if (ctx->family == AF_INET) {
        __builtin_memcpy(k.saddr, ctx->saddr, 4);
        __builtin_memcpy(k.daddr, ctx->daddr, 4);
    } else if (ctx->family == AF_INET6) {
        __builtin_memcpy(k.saddr, ctx->saddr_v6, 16);
        __builtin_memcpy(k.daddr, ctx->daddr_v6, 16);
    } else {
        return 0;
    }

    __u64 now = bpf_ktime_get_ns();
    __u64 skaddr = (__u64)(unsigned long)ctx->skaddr;

    struct net_val *v = bpf_map_lookup_elem(&net_conn_map, &k);
    if (!v) {
        struct net_val nv = {
            .first_seen_ns = now,
            .last_seen_ns  = now,
            .state         = (__u32)ctx->newstate,
        };
        if (ctx->newstate == TCP_SYN_SENT)
            nv.syn_sent_ns = now;
        bpf_map_update_elem(&net_conn_map, &k, &nv, BPF_ANY);
    } else {
        v->last_seen_ns = now;
        v->state = (__u32)ctx->newstate;
        if (ctx->newstate == TCP_SYN_SENT)
            v->syn_sent_ns = now;
        if (ctx->newstate == TCP_ESTABLISHED && v->syn_sent_ns != 0 && v->established_ns == 0) {
            v->established_ns = now;
            v->rtt_ns = now - v->syn_sent_ns;
        }
    }

    // Mantém sock_to_key vivo enquanto a conexão existe; remove ao fechar.
    if (ctx->newstate == TCP_CLOSE) {
        bpf_map_delete_elem(&sock_to_key, &skaddr);
    } else {
        bpf_map_update_elem(&sock_to_key, &skaddr, &k, BPF_ANY);
    }
    return 0;
}

// add_bytes faz lookup do sk → net_key → net_val e acumula bytes no campo
// indicado. Inline pra evitar overhead de chamada e satisfazer verifier.
static __always_inline void add_bytes(__u64 skaddr, __u64 bytes, int is_tx)
{
    struct net_key *kp = bpf_map_lookup_elem(&sock_to_key, &skaddr);
    if (!kp)
        return;
    // Copia pra stack — verifier preferere não passar ponteiros pra map
    // memory como key de outro lookup em algumas versões.
    struct net_key k = *kp;
    struct net_val *v = bpf_map_lookup_elem(&net_conn_map, &k);
    if (!v)
        return;
    if (is_tx)
        __sync_fetch_and_add(&v->tx_bytes, bytes);
    else
        __sync_fetch_and_add(&v->rx_bytes, bytes);
    v->last_seen_ns = bpf_ktime_get_ns();
}

// tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
// PARM1 = sk, PARM3 = size (em bytes — request, não retorno).
// Pra MVP usamos o size como "bytes Tx" — em prática é o que foi enfileirado;
// erro raro (-EAGAIN, etc.) ainda contaria. Aceitável.
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(handle_tcp_sendmsg, void *sk, void *msg, __u64 size)
{
    if (!is_net_target())
        return 0;
    if (size == 0)
        return 0;
    add_bytes((__u64)(unsigned long)sk, size, 1);
    return 0;
}

// tcp_cleanup_rbuf(struct sock *sk, int copied) é chamada quando bytes
// recebidos foram entregues ao userspace e o receive buffer pode liberar.
// PARM1 = sk, PARM2 = copied (bytes efetivamente entregues).
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(handle_tcp_cleanup_rbuf, void *sk, int copied)
{
    if (!is_net_target())
        return 0;
    if (copied <= 0)
        return 0;
    add_bytes((__u64)(unsigned long)sk, (__u64)copied, 0);
    return 0;
}
