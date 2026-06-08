// SPDX-License-Identifier: GPL-2.0
//
// network.bpf.c — traces TCP connections of the target PID:
//
//   1. tracepoint sock:inet_sock_set_state → discovers 5-tuple + state
//   2. kprobe   tcp_sendmsg                → Tx bytes
//   3. kprobe   tcp_cleanup_rbuf           → Rx bytes
//   4. kprobe   tcp_reset                  → connection refused / reset (#56)
//   5. kprobe   tcp_retransmit_skb         → retransmit / timeout backoff (#56)
//
// Trick to avoid dereferencing `struct sock` (which would require vmlinux.h
// or fragile manual offsets): the inet_sock_set_state tracepoint already
// delivers `skaddr` (the kernel sock pointer) ALONG WITH the 5-tuple, so we
// keep an auxiliary sock_to_key map (skaddr → net_key). The kprobes on
// tcp_sendmsg/cleanup_rbuf receive `struct sock *sk` as their first arg via
// PT_REGS_PARM1 — they use the pointer as the sock_to_key lookup key and
// accumulate bytes in the corresponding net_val, without reading any field
// of the sock.
//
// Maps:
//   net_target_pid    ARRAY[1]  struct target_filter (written by the Go loader)
//   net_conn_map      HASH      net_key → net_val (state, RTT, tx/rx, retransmits)
//   sock_to_key       HASH      sock_ptr → net_key (correlation)
//   net_error_events  RINGBUF   per-event channel → user-space (#56 net errors)
//
// Net errors (#56): tcp_reset fires on an incoming RST — we classify it as
// "refused" (RST while we still track the conn as SYN_SENT) vs "reset"
// (RST on an ESTABLISHED conn) from the state we already hold in net_conn_map.
// tcp_retransmit_skb fires per retransmit, carrying the conn's running count
// (backoff is visible as the count grows).
//
// Target filtering on these two probes is DIFFERENT from the byte kprobes:
// RST handling and the retransmit timer run in softirq/timer context, where
// the "current task" is whoever was interrupted — almost never our target, so
// pid_is_target() would drop nearly every event. Instead these probes rely
// purely on sock_to_key membership: that map is only ever populated under
// pid_is_target() (in the process-context connect/accept path of
// inet_sock_set_state), so a hit there already means "the target's socket".
//
// Limitations:
//   - Pre-existing connections (opened before ptop attached) don't enter
//     sock_to_key, so tx/rx and net errors stay absent for them. New ones work.
//   - the pid filter resolves the *current* task; in softirq that is the
//     interrupted task, so it may skip or misattribute on the softirq path.
//     tcp_sendmsg/cleanup_rbuf run in process context, so OK.

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "target.bpf.h"

char LICENSE[] SEC("license") = "GPL";

#define AF_INET  2
#define AF_INET6 10

#define IPPROTO_TCP 6

#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT    2
#define TCP_CLOSE       7

// Layout of the sock:inet_sock_set_state tracepoint — stable since 4.16.
// kernel emits sport/dport already in host-order (ntohs), addrs in network order.
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

// net_key: 5-tuple. For IPv4, the first 4 bytes of saddr/daddr are
// significant and the rest are zero. Fixed layout (40 bytes) matching
// NetConnKey in internal/bpf/network.go.
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
    __u32 retransmits; // #56 — running tcp_retransmit_skb count for this conn
};

// Net error kinds — must match netErrKind* in internal/bpf/network.go.
#define NET_ERR_REFUSED    0 // RST received while the conn was still SYN_SENT
#define NET_ERR_RESET      1 // RST received on an ESTABLISHED conn
#define NET_ERR_RETRANSMIT 2 // tcp_retransmit_skb fired

// net_error_event is published to user-space via the net_error_events ring
// buffer. Fixed layout (64 bytes), read with binary.LittleEndian on the Go
// side — keep in sync with NetErrorRecord in internal/bpf/network.go.
struct net_error_event {
    __u64 ts_ns;
    struct net_key key;   // 5-tuple, to correlate with a connection (40 bytes)
    __u32 kind;           // NET_ERR_*
    __u32 retransmits;    // running retransmit count (RETRANSMIT kind)
    __u64 detail_ns;      // latency-to-RST (refused/reset); 0 otherwise
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct target_filter);
    __uint(max_entries, 1);
} net_target_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct net_key);
    __type(value, struct net_val);
    __uint(max_entries, 4096);
} net_conn_map SEC(".maps");

// sock_to_key: kernel sock pointer → 5-tuple, used to correlate kprobes
// (which receive sk as an arg) with net_conn_map (keyed by 5-tuple).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct net_key);
    __uint(max_entries, 4096);
} sock_to_key SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); // 256KB — net errors are low-rate
} net_error_events SEC(".maps");

static __always_inline int is_net_target(void)
{
    return pid_is_target(&net_target_pid);
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

    // Keep sock_to_key alive while the connection exists; remove on close.
    if (ctx->newstate == TCP_CLOSE) {
        bpf_map_delete_elem(&sock_to_key, &skaddr);
    } else {
        bpf_map_update_elem(&sock_to_key, &skaddr, &k, BPF_ANY);
    }
    return 0;
}

// add_bytes does sk → net_key → net_val lookup and accumulates bytes in the
// indicated field. Inlined to avoid call overhead and satisfy the verifier.
static __always_inline void add_bytes(__u64 skaddr, __u64 bytes, int is_tx)
{
    struct net_key *kp = bpf_map_lookup_elem(&sock_to_key, &skaddr);
    if (!kp)
        return;
    // Copy to stack — the verifier prefers not passing pointers into map
    // memory as a key for another lookup in some versions.
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
// PARM1 = sk, PARM3 = size (in bytes — request, not return value).
// For the MVP we use size as "Tx bytes" — in practice it's what was queued;
// rare errors (-EAGAIN, etc.) would still count. Acceptable.
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

// tcp_cleanup_rbuf(struct sock *sk, int copied) is called when received
// bytes have been delivered to userspace and the receive buffer can be freed.
// PARM1 = sk, PARM2 = copied (bytes actually delivered).
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

// emit_net_error reserves a ring-buffer slot and publishes one error event.
// kp points at a stack copy of the 5-tuple (never into map memory).
static __always_inline void emit_net_error(struct net_key *kp, __u32 kind,
                                           __u32 retransmits, __u64 detail_ns)
{
    struct net_error_event *e = bpf_ringbuf_reserve(&net_error_events, sizeof(*e), 0);
    if (!e)
        return;
    e->ts_ns       = bpf_ktime_get_ns();
    e->key         = *kp;
    e->kind        = kind;
    e->retransmits = retransmits;
    e->detail_ns   = detail_ns;
    bpf_ringbuf_submit(e, 0);
}

// tcp_reset(struct sock *sk, ...) runs when an incoming RST tears the conn
// down. PARM1 = sk. No pid filter here (softirq context) — sock_to_key
// membership is the target filter (see the file header). The conn's CURRENT
// state in net_conn_map distinguishes a refused connect (SYN_SENT) from a
// mid-stream reset (ESTABLISHED): this kprobe fires before the subsequent
// inet_sock_set_state(→CLOSE), so the pre-reset state is still recorded.
SEC("kprobe/tcp_reset")
int BPF_KPROBE(handle_tcp_reset, void *sk)
{
    __u64 skaddr = (__u64)(unsigned long)sk;
    struct net_key *kp = bpf_map_lookup_elem(&sock_to_key, &skaddr);
    if (!kp)
        return 0;
    struct net_key k = *kp; // stack copy before the second lookup (verifier)
    struct net_val *v = bpf_map_lookup_elem(&net_conn_map, &k);
    if (!v)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u32 kind;
    __u64 detail = 0;
    if (v->state == TCP_SYN_SENT) {
        kind = NET_ERR_REFUSED;
        if (v->syn_sent_ns)
            detail = now - v->syn_sent_ns;
    } else {
        kind = NET_ERR_RESET;
        if (v->established_ns)
            detail = now - v->established_ns;
    }
    emit_net_error(&k, kind, v->retransmits, detail);
    return 0;
}

// tcp_retransmit_skb(struct sock *sk, ...) fires once per retransmitted skb.
// PARM1 = sk. Same softirq/timer-context reasoning as tcp_reset: filter by
// sock_to_key membership, not the current task. Each fire bumps the conn's
// running count and emits it (RTO backoff shows up as the count climbing).
SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(handle_tcp_retransmit, void *sk)
{
    __u64 skaddr = (__u64)(unsigned long)sk;
    struct net_key *kp = bpf_map_lookup_elem(&sock_to_key, &skaddr);
    if (!kp)
        return 0;
    struct net_key k = *kp;
    struct net_val *v = bpf_map_lookup_elem(&net_conn_map, &k);
    if (!v)
        return 0;
    // Increment as a statement, then read the field back: the BPF target
    // rejects using the XADD return value as an rvalue ("Invalid usage of the
    // XADD return value") on the default cpu. The read may race a concurrent
    // bump, but a slightly-ahead retransmit counter is fine for display.
    __sync_fetch_and_add(&v->retransmits, 1);
    emit_net_error(&k, NET_ERR_RETRANSMIT, v->retransmits, 0);
    return 0;
}
