// SPDX-License-Identifier: GPL-2.0
//
// network.bpf.c — rastreia conexões TCP do PID alvo via tracepoint
// sock:inet_sock_set_state (estável desde kernel 4.16). Esse tracepoint
// entrega a 5-tuple e family direto nos args, sem precisar dereferenciar
// `struct sock` — evita dependência de vmlinux.h ou CO-RE.
//
// Maps:
//   net_target_pid   ARRAY[1]  pid alvo (escrito pelo loader Go)
//   net_conn_map     HASH      net_key → net_val
//                              key = (daddr, saddr, dport, sport, family)
//                              val = state, first/last_seen, syn_sent/estab,
//                                    rtt_ns (established - syn_sent)
//
// Latência: medida no handshake (transição SYN_SENT → ESTABLISHED da mesma
// 5-tuple) como sample inicial de RTT. Bytes Tx/Rx ficam para uma segunda
// fase (requer kprobes em tcp_sendmsg/cleanup_rbuf com leitura de sock,
// que demanda vmlinux.h ou offsets manuais — fora do escopo deste passe).
//
// Filtro de PID: bpf_get_current_pid_tgid() é confiável apenas em syscall
// context (process). Estados disparados em softirq (TIME_WAIT, etc.) podem
// vir com tgid=0 e ser descartados — limitação aceita; conexões iniciadas
// pelo processo (SYN_SENT, ESTABLISHED) chegam corretamente.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define AF_INET  2
#define AF_INET6 10

#define IPPROTO_TCP 6

// TCP states do kernel (linux/tcp.h) — replicados pra evitar include.
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT    2

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
        return 0;
    }

    v->last_seen_ns = now;
    v->state = (__u32)ctx->newstate;
    if (ctx->newstate == TCP_SYN_SENT)
        v->syn_sent_ns = now;
    if (ctx->newstate == TCP_ESTABLISHED && v->syn_sent_ns != 0 && v->established_ns == 0) {
        v->established_ns = now;
        v->rtt_ns = now - v->syn_sent_ns;
    }
    return 0;
}
