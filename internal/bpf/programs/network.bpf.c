// SPDX-License-Identifier: GPL-2.0
//
// network.bpf.c — the target's TCP connections: who it talks to, how much
// moves, how long the handshake took, and what went wrong.
//
//   tracepoint sock:inet_sock_set_state → every state transition
//   tracepoint sock:sock_send_length    → Tx bytes (6.4+)
//   tracepoint sock:sock_recv_length    → Rx bytes (6.4+)
//   kprobe     tcp_sendmsg              → Tx bytes, kernels without those tracepoints
//   kprobe     tcp_cleanup_rbuf         → Rx bytes, kernels without those tracepoints
//   kprobe     tcp_reset                → connection refused / reset (#56)
//   kprobe     tcp_retransmit_skb       → retransmit / timeout backoff (#56)
//
// OWNERSHIP IS DECIDED BY EVIDENCE, NEVER BY `current` IN SOFTIRQ (#135)
//
// Most TCP transitions do not run in the owner's context. The handshake
// completing, a FIN or an RST arriving, the final ACK: all of it is packet
// processing, in softirq, where `current` is whatever task the interrupt
// happened to land on. Filtering those on the target's pid was wrong in both
// directions, and both were measured:
//
//   - The target's own transitions were dropped. Against a peer that is not on
//     loopback, SYN_SENT → ESTABLISHED arrived in the target's context 0 times
//     out of 24, and CLOSE 5 times out of 24 — so a connection never reached
//     ESTABLISHED and almost never reached CLOSE, which is the only state
//     userspace prunes on (#133).
//   - Other processes' transitions were admitted. On loopback the softirq runs
//     in the SENDER's context, so the FIN of the target's own close() moved
//     the PEER's socket — another process's — to CLOSE_WAIT inside the
//     target's context; and a busy target is whoever the NIC interrupt lands
//     on. A target that owned no socket at all was credited with 1,582
//     connections in fifteen seconds.
//
// So a socket becomes the target's only on evidence that it is:
//
//   1. the target called connect() on it — SYN_SENT is set inside the syscall,
//      in the caller's context, so there `current` IS the evidence;
//   2. the target sent or received on it — the byte probes run in the context
//      of the task doing the I/O;
//   3. its 4-tuple names a row already proven to be the target's — which is
//      what the userspace seed is: it reads /proc/<pid>/fd (#142);
//   4. the target listen()ed on it or closed it — LISTEN, FIN_WAIT1 and
//      LAST_ACK are set only by the owner's own syscalls.
//
// Once a socket is owned (sock_to_key), every transition follows it, in any
// context. That is what brings back ESTABLISHED (the handshake RTT) and CLOSE
// (the prune).
//
// NO KEY AT SYN_SENT
//
// tcp_v4_connect() sets SYN_SENT BEFORE inet_hash_connect() picks the source
// port, so the tracepoint reports sport=0 there (measured, every connect).
// Keying on it made every connection to one peer share a key: one immortal
// SYN_SENT row absorbed all of their bytes, and the handshake RTT was never
// computed at all, because ESTABLISHED carries the real port and therefore a
// different key. SYN_SENT now only notes the socket in `connecting`; its row
// is keyed when it leaves SYN_SENT, by which time the port exists.
//
// The tracepoint keys from its own fields. The probes that are handed only a
// socket pointer read the same identity out of sk->__sk_common (CO-RE) — the
// fields /proc/net/tcp prints, so a seeded key and an adopted one match byte
// for byte. That read needs the kernel's BTF (/sys/kernel/btf/vmlinux); the
// loader says so by name when it is missing.
//
// BYTES
//
// The sock_{send,recv}_length tracepoints (6.4+) fire in sock_{send,recv}msg
// with the exact count. The kprobes before them hang on functions the compiler
// may inline: measured on a 7.2 kernel, tcp_recvmsg's final tcp_cleanup_rbuf()
// call is inlined and the kprobe saw copied <= 0 only, so Rx was zero for every
// connection. A tracepoint cannot be inlined away. The kprobes remain as the
// lane for kernels that predate it.
//
// Net errors (#56): tcp_reset fires on an incoming RST and is classified from
// the socket's own state at that moment — SYN_SENT is "refused", anything else
// "reset", which is the kernel's own classification in tcp_reset().
// tcp_retransmit_skb fires per retransmit, with the conn's running count.

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "target.bpf.h"

char LICENSE[] SEC("license") = "GPL";

#define AF_INET  2
#define AF_INET6 10

#define IPPROTO_TCP 6

#define MSG_PEEK 2

#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT    2
#define TCP_FIN_WAIT1   4
#define TCP_CLOSE       7
#define TCP_LAST_ACK    9
#define TCP_LISTEN      10

// The slice of struct sock this program reads, relocated against the running
// kernel's BTF (CO-RE). Field names are what is matched, so the layout here is
// irrelevant; the ___ptop suffix keeps the names from clashing with any header.
struct in6_addr___ptop {
    __u8 b[16];
};

struct sock_common___ptop {
    __be32 skc_daddr;
    __be32 skc_rcv_saddr;
    __be16 skc_dport;
    __u16 skc_num;
    unsigned short skc_family;
    volatile unsigned char skc_state;
    struct in6_addr___ptop skc_v6_daddr;
    struct in6_addr___ptop skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

struct sock___ptop {
    struct sock_common___ptop __sk_common;
} __attribute__((preserve_access_index));

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

// Layout of sock:sock_send_length / sock:sock_recv_length (6.4+, one event
// class, unchanged since it was added).
struct sock_length_args {
    unsigned long long _pad;
    const void *sk;
    __u16 family;
    __u16 protocol;
    int ret;
    int flags;
};

// net_key: 4-tuple + family, as the socket holds it: addresses in network
// order (the first 4 bytes for IPv4, the rest zero), ports in host order.
// Fixed layout (40 bytes) matching NetConnKey in internal/bpf/network.go.
struct net_key {
    __u8  daddr[16];
    __u8  saddr[16];
    __u16 dport;
    __u16 sport;
    __u16 family;
    __u16 _pad;
};

// Flags on a net_val — must match netFlag* in internal/bpf/network.go.
#define NET_F_RTT 1 // rtt_ns is a measurement: this program saw the handshake

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
    __u32 flags;       // NET_F_*
    __u32 _pad;
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

// sock_to_key: the sockets the target is proven to own, kernel sock pointer →
// 4-tuple. Membership IS ownership: every probe that cannot trust `current`
// filters on it. LRU so that an entry orphaned by a race (an adoption landing
// just after the socket's CLOSE) is eventually evicted instead of standing in
// for whatever socket reuses the address; a live entry evicted under pressure
// is re-adopted by tuple on its socket's next event.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);
    __type(value, struct net_key);
    __uint(max_entries, 4096);
} sock_to_key SEC(".maps");

// connecting: sockets the target has called connect() on, sock pointer →
// SYN_SENT timestamp. Held until the socket has a source port and leaves
// SYN_SENT, which is when it gets a row; the timestamp becomes its handshake
// RTT.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 4096);
} connecting SEC(".maps");

// net_stats counts what this program could not record (#133).
//
// net_conn_map is a fixed-size HASH, and a full one refuses an insert with
// -E2BIG. The return used to be discarded, so a saturated map meant new
// connections silently ceased to exist: no row, and no bytes either, since
// add_bytes needs the entry. Measured, the map filled in twelve seconds under
// short-lived connections.
//
// Userspace now prunes closed entries so it should not fill at all. This
// counter is what makes that claim checkable rather than assumed — and if the
// pruning is ever outrun, an axis that says how much it missed beats one that
// goes quietly blind (#112).
struct net_stats {
    __u64 conn_insert_failed;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct net_stats);
    __uint(max_entries, 1);
} net_stats SEC(".maps");

static __always_inline void note_insert_failed(void)
{
    __u32 k = 0;
    struct net_stats *st = bpf_map_lookup_elem(&net_stats, &k);
    if (st)
        st->conn_insert_failed += 1;
}

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); // 256KB — net errors are low-rate
} net_error_events SEC(".maps");

static __always_inline int is_net_target(void)
{
    return pid_is_target(&net_target_pid);
}

// key_from_sock reads a socket's identity out of the socket itself. Returns 0
// for anything that is not an IPv4/IPv6 socket with a peer: a listening or an
// unconnected socket has no connection to name.
static __always_inline int key_from_sock(const void *skp, struct net_key *k)
{
    const struct sock___ptop *sk = skp;

    __builtin_memset(k, 0, sizeof(*k));
    k->family = BPF_CORE_READ(sk, __sk_common.skc_family);
    k->sport  = BPF_CORE_READ(sk, __sk_common.skc_num);
    k->dport  = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    if (k->family == AF_INET) {
        __be32 s = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __be32 d = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(k->saddr, &s, 4);
        __builtin_memcpy(k->daddr, &d, 4);
    } else if (k->family == AF_INET6) {
        BPF_CORE_READ_INTO(&k->saddr, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&k->daddr, sk, __sk_common.skc_v6_daddr);
    } else {
        return 0;
    }
    return k->dport != 0;
}

// key_from_ctx names the socket a state transition is about, from the
// tracepoint's own fields — no socket read. Never valid at SYN_SENT, where the
// source port is still 0 (see the file header).
static __always_inline int key_from_ctx(struct sock_set_state_args *ctx, struct net_key *k)
{
    __builtin_memset(k, 0, sizeof(*k));
    k->family = ctx->family;
    k->sport  = ctx->sport;
    k->dport  = ctx->dport;
    if (ctx->family == AF_INET) {
        __builtin_memcpy(k->saddr, ctx->saddr, 4);
        __builtin_memcpy(k->daddr, ctx->daddr, 4);
    } else if (ctx->family == AF_INET6) {
        __builtin_memcpy(k->saddr, ctx->saddr_v6, 16);
        __builtin_memcpy(k->daddr, ctx->daddr_v6, 16);
    } else {
        return 0;
    }
    return 1;
}

// own_sock records that the target owns `sk`: it makes sure the socket's row
// exists and registers the socket, so that every later event on it — in any
// context — is attributed. A socket the target is connect()ing carries its
// SYN_SENT time over, which is what lets ESTABLISHED compute the handshake.
//
// Returns the row, or NULL when a map was full (counted).
static __always_inline struct net_val *own_sock(__u64 skaddr, struct net_key *k,
                                               __u32 state, __u64 now)
{
    struct net_val *v = bpf_map_lookup_elem(&net_conn_map, k);
    if (!v) {
        struct net_val nv = {
            .first_seen_ns = now,
            .last_seen_ns  = now,
            .state         = state,
        };
        __u64 *syn = bpf_map_lookup_elem(&connecting, &skaddr);
        if (syn) {
            nv.first_seen_ns = *syn;
            nv.syn_sent_ns   = *syn;
        }
        if (bpf_map_update_elem(&net_conn_map, k, &nv, BPF_NOEXIST) < 0) {
            // Lost a race to another CPU creating the same row, or full.
            v = bpf_map_lookup_elem(&net_conn_map, k);
            if (!v) {
                note_insert_failed();
                return 0;
            }
        } else {
            v = bpf_map_lookup_elem(&net_conn_map, k);
            if (!v)
                return 0;
        }
    }
    if (state != TCP_CLOSE &&
        bpf_map_update_elem(&sock_to_key, &skaddr, k, BPF_ANY) < 0)
        note_insert_failed();
    return v;
}

// owned_row returns the row of a socket the target owns, or NULL. A socket in
// sock_to_key whose row is gone — userspace pruned it after a CLOSE this map
// missed — is not owned any more.
static __always_inline struct net_val *owned_row(__u64 skaddr, struct net_key *k)
{
    struct net_key *kp = bpf_map_lookup_elem(&sock_to_key, &skaddr);
    if (!kp)
        return 0;
    // Copy to stack — the verifier prefers not passing pointers into map
    // memory as a key for another lookup in some versions.
    *k = *kp;
    struct net_val *v = bpf_map_lookup_elem(&net_conn_map, k);
    if (!v)
        bpf_map_delete_elem(&sock_to_key, &skaddr);
    return v;
}

// adopt_by_tuple is evidence 3: a socket nobody registered whose 4-tuple names
// a row that already exists — seeded from /proc/<pid>/fd, or created by one of
// the other kinds of evidence. A live 4-tuple names one socket, so the row's
// owner is this socket's owner. Registers the socket on a hit.
static __always_inline struct net_val *adopt_by_tuple(__u64 skaddr, struct net_key *k,
                                                      __u32 state, __u64 now)
{
    if (!bpf_map_lookup_elem(&net_conn_map, k))
        return 0;
    return own_sock(skaddr, k, state, now);
}

static __always_inline void apply_state(struct net_val *v, __u32 state, __u64 now)
{
    v->last_seen_ns = now;
    v->state = state;
    if (state == TCP_ESTABLISHED && v->syn_sent_ns != 0 && !(v->flags & NET_F_RTT)) {
        v->established_ns = now;
        v->rtt_ns = now - v->syn_sent_ns;
        v->flags |= NET_F_RTT;
    }
}

SEC("tracepoint/sock/inet_sock_set_state")
int handle_inet_set_state(struct sock_set_state_args *ctx)
{
    if (ctx->protocol != IPPROTO_TCP)
        return 0;
    if (ctx->family != AF_INET && ctx->family != AF_INET6)
        return 0;

    __u64 skaddr = (__u64)(unsigned long)ctx->skaddr;
    __u32 newstate = (__u32)ctx->newstate;
    __u64 now = bpf_ktime_get_ns();
    struct net_key k;

    // Already the target's: follow it, whatever context this runs in.
    struct net_val *v = owned_row(skaddr, &k);
    if (v) {
        apply_state(v, newstate, now);
        if (newstate == TCP_CLOSE)
            bpf_map_delete_elem(&sock_to_key, &skaddr);
        if (newstate != TCP_SYN_SENT)
            bpf_map_delete_elem(&connecting, &skaddr);
        return 0;
    }

    if (newstate == TCP_SYN_SENT) {
        // Evidence 1, but no row yet: the source port is not chosen until
        // after this transition (sport=0 here), so there is no key to give.
        if (!is_net_target())
            return 0;
        bpf_map_update_elem(&connecting, &skaddr, &now, BPF_ANY);
        return 0;
    }

    if (!key_from_ctx(ctx, &k))
        return 0;

    // A connect() the target started, now leaving SYN_SENT — established in
    // softirq, or refused. The port exists now.
    if (bpf_map_lookup_elem(&connecting, &skaddr)) {
        v = own_sock(skaddr, &k, newstate, now);
        if (v)
            apply_state(v, newstate, now);
        bpf_map_delete_elem(&connecting, &skaddr);
        return 0;
    }

    // Evidence 3: a row already proven names this socket.
    v = adopt_by_tuple(skaddr, &k, newstate, now);
    if (v) {
        apply_state(v, newstate, now);
        return 0;
    }

    // Evidence 4: transitions only the owner's own syscalls make. Everything
    // else may be softirq, where `current` proves nothing.
    if (newstate != TCP_LISTEN && newstate != TCP_FIN_WAIT1 && newstate != TCP_LAST_ACK)
        return 0;
    if (!is_net_target())
        return 0;
    v = own_sock(skaddr, &k, newstate, now);
    if (v)
        apply_state(v, newstate, now);
    return 0;
}

// add_bytes credits I/O the target did on `sk`. The caller has already checked
// is_net_target(), so an unknown socket is adopted here: the target reading or
// writing it is evidence 2 — which is how a server's accepted connections
// (#135) and connections older than the capture (#142) get their bytes.
static __always_inline void add_bytes(const void *sk, __u64 bytes, int is_tx)
{
    __u64 skaddr = (__u64)(unsigned long)sk;
    struct net_key k;
    __u64 now = bpf_ktime_get_ns();

    struct net_val *v = owned_row(skaddr, &k);
    if (!v) {
        if (!key_from_sock(sk, &k))
            return;
        __u32 state = BPF_CORE_READ((const struct sock___ptop *)sk, __sk_common.skc_state);
        v = own_sock(skaddr, &k, state, now);
        if (!v)
            return;
    }
    if (is_tx)
        __sync_fetch_and_add(&v->tx_bytes, bytes);
    else
        __sync_fetch_and_add(&v->rx_bytes, bytes);
    v->last_seen_ns = now;
}

// sock_send_length / sock_recv_length fire for every socket family, after the
// protocol's sendmsg/recvmsg returned; ret is what it returned.
SEC("tracepoint/sock/sock_send_length")
int handle_send_length(struct sock_length_args *ctx)
{
    if (ctx->protocol != IPPROTO_TCP || ctx->ret <= 0)
        return 0;
    if (ctx->family != AF_INET && ctx->family != AF_INET6)
        return 0;
    if (!is_net_target())
        return 0;
    add_bytes(ctx->sk, (__u64)ctx->ret, 1);
    return 0;
}

SEC("tracepoint/sock/sock_recv_length")
int handle_recv_length(struct sock_length_args *ctx)
{
    if (ctx->protocol != IPPROTO_TCP || ctx->ret <= 0)
        return 0;
    if (ctx->family != AF_INET && ctx->family != AF_INET6)
        return 0;
    if (ctx->flags & MSG_PEEK) // the bytes stay queued; the real read counts them
        return 0;
    if (!is_net_target())
        return 0;
    add_bytes(ctx->sk, (__u64)ctx->ret, 0);
    return 0;
}

// tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
// PARM1 = sk, PARM3 = size (the request, not the return value — a short or
// failed send still counts its full size). The lane for kernels without
// sock:sock_send_length.
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(handle_tcp_sendmsg, void *sk, void *msg, __u64 size)
{
    if (size == 0)
        return 0;
    if (!is_net_target())
        return 0;
    add_bytes(sk, size, 1);
    return 0;
}

// tcp_cleanup_rbuf(struct sock *sk, int copied) runs when received bytes have
// been delivered to userspace. PARM1 = sk, PARM2 = copied. The lane for kernels
// without sock:sock_recv_length — and an inlining candidate (see the header).
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(handle_tcp_cleanup_rbuf, void *sk, int copied)
{
    if (copied <= 0)
        return 0;
    if (!is_net_target())
        return 0;
    add_bytes(sk, (__u64)copied, 0);
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

// error_row finds the target's row for a socket an error probe fired on. These
// run in softirq/timer context, so `current` proves nothing: the socket must be
// owned already, be one the target is connect()ing (a refused connect, a SYN
// retransmit — it gets its row here, with the port it now has), or name a
// proven row by tuple.
static __always_inline struct net_val *error_row(const void *sk, struct net_key *k, __u64 now)
{
    __u64 skaddr = (__u64)(unsigned long)sk;
    struct net_val *v = owned_row(skaddr, k);
    if (v)
        return v;
    if (!key_from_sock(sk, k))
        return 0;
    if (bpf_map_lookup_elem(&connecting, &skaddr))
        return own_sock(skaddr, k, TCP_SYN_SENT, now);
    __u32 state = BPF_CORE_READ((const struct sock___ptop *)sk, __sk_common.skc_state);
    return adopt_by_tuple(skaddr, k, state, now);
}

// tcp_reset(struct sock *sk, ...) runs when an incoming RST tears the conn
// down, before the state moves to CLOSE. PARM1 = sk. The socket's state at
// this moment is the one tcp_reset() itself switches on: SYN_SENT means the
// connect was refused, anything else is a reset.
SEC("kprobe/tcp_reset")
int BPF_KPROBE(handle_tcp_reset, void *sk)
{
    __u64 now = bpf_ktime_get_ns();
    struct net_key k;
    struct net_val *v = error_row(sk, &k, now);
    if (!v)
        return 0;

    __u32 state = BPF_CORE_READ((const struct sock___ptop *)sk, __sk_common.skc_state);
    __u32 kind;
    __u64 detail = 0;
    if (state == TCP_SYN_SENT) {
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

// tcp_retransmit_skb(struct sock *sk, ...) fires once per retransmitted skb,
// SYNs included. PARM1 = sk. Each fire bumps the conn's running count and
// emits it (RTO backoff shows up as the count climbing).
SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(handle_tcp_retransmit, void *sk)
{
    struct net_key k;
    struct net_val *v = error_row(sk, &k, bpf_ktime_get_ns());
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
