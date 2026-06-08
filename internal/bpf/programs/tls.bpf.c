// SPDX-License-Identifier: GPL-2.0
//
// tls.bpf.c — pre-encryption / post-decryption TLS payload capture (#55).
//
// Uprobes the target's TLS library (OpenSSL/BoringSSL libssl) to observe the
// PLAINTEXT around encryption, attached by symbol from the Go loader (see
// internal/bpf/tls.go), exactly like the heap collector uprobes libc:
//   uprobe   SSL_write(ssl, buf, num)  → plaintext is in buf at entry (to send)
//   uprobe   SSL_read(ssl, buf, num)   → stash buf; the kernel fills it later
//   uretprobe SSL_read(ret)            → buf now holds `ret` decrypted bytes
//   uprobe   SSL_set_fd(ssl, fd)       → remember ssl→fd for connection corr.
//
// PRIVACY: this captures plaintext (credentials, PII). It is OFF unless the
// user passes --tls, and the actual bytes are copied only when --tls-bytes N
// is set (tls_cfg holds N, capped at TLS_MAX_DATA). With N=0 only metadata
// (direction, fd, byte count) is emitted — never the payload. See #55 / README.
//
// Maps:
//   tls_target_pid  ARRAY[1]  struct target_filter (Go loader writes it)
//   tls_cfg         ARRAY[1]  __u32 — max plaintext bytes to copy (0 = none)
//   tls_ssl_fd      HASH      ssl_ptr → fd (from SSL_set_fd)
//   tls_read_args   HASH      pid_tgid → {ssl, buf} (SSL_read entry→ret)
//   tls_events      RINGBUF   per-call payload events → user-space

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "target.bpf.h"

char LICENSE[] SEC("license") = "GPL";

#define TLS_DIR_WRITE 0 // SSL_write — plaintext being sent (pre-encryption)
#define TLS_DIR_READ  1 // SSL_read  — plaintext received (post-decryption)

// Hard cap on bytes copied per call. The configured --tls-bytes is clamped to
// this; the event carries a fixed buffer of this size (only `captured` valid).
#define TLS_MAX_DATA 4096

struct read_args {
    __u64 ssl;
    __u64 buf;
};

// tls_event is published to user-space via the tls_events ring buffer. Fixed
// layout, read with binary.LittleEndian on the Go side — keep in sync with
// TLSEventRecord in internal/bpf/tls.go. Only the first `captured` bytes of
// data are valid.
struct tls_event {
    __u64 ts_ns;
    __u32 tgid;
    __u32 pid; // tid
    __s32 fd;  // owning socket fd (−1 if SSL_set_fd wasn't seen)
    __u32 dir; // TLS_DIR_*
    __s32 len; // plaintext byte count for the call (num / read retval)
    __u32 captured;
    char  data[TLS_MAX_DATA];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct target_filter);
    __uint(max_entries, 1);
} tls_target_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32); // max plaintext bytes to copy (0 = metadata only)
    __uint(max_entries, 1);
} tls_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);  // ssl pointer
    __type(value, __s32); // fd
    __uint(max_entries, 4096);
} tls_ssl_fd SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64); // pid_tgid
    __type(value, struct read_args);
    __uint(max_entries, 10240);
} tls_read_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 21); // 2MB — opt-in, payloads can be large
} tls_events SEC(".maps");

static __always_inline int is_tls_target(void)
{
    return pid_is_target(&tls_target_pid);
}

// emit_payload reserves a ring-buffer slot and publishes one TLS payload event.
// It copies up to min(len, configured-cap) plaintext bytes from buf — and zero
// bytes when the cap is 0 (metadata-only mode).
static __always_inline void emit_payload(__u32 dir, __u64 ssl, __u64 buf, __s64 len)
{
    if (len <= 0)
        return;

    __u32 zero = 0;
    __u32 *cfgp = bpf_map_lookup_elem(&tls_cfg, &zero);
    __u64 cap = cfgp ? (__u64)*cfgp : 0; // map-derived → verifier can't bound it

    // captured = min(len, cap), then masked to [0, TLS_MAX_DATA-1]. The mask is
    // the SOLE bound — we deliberately do NOT clamp cap first, because clang
    // would then prove captured ≤ TLS_MAX_DATA-1 and eliminate the mask, leaving
    // the verifier with an unbounded length ("R2 min value is negative"). The Go
    // loader clamps tls_cfg to TLS_MAX_DATA-1, so the mask never truncates.
    __u32 captured = 0;
    if (len > 0) {
        __u64 n = (__u64)len;
        if (n > cap)
            n = cap;
        captured = (__u32)n & (TLS_MAX_DATA - 1);
    }

    struct tls_event *e = bpf_ringbuf_reserve(&tls_events, sizeof(*e), 0);
    if (!e)
        return;
    __u64 pt = bpf_get_current_pid_tgid();
    e->ts_ns    = bpf_ktime_get_ns();
    e->tgid     = (__u32)(pt >> 32);
    e->pid      = (__u32)pt;
    __s32 *fdp  = bpf_map_lookup_elem(&tls_ssl_fd, &ssl);
    e->fd       = fdp ? *fdp : -1;
    e->dir      = dir;
    e->len      = (__s32)len;
    e->captured = captured;
    if (captured > 0)
        bpf_probe_read_user(e->data, captured, (const void *)buf);
    bpf_ringbuf_submit(e, 0);
}

// SSL_write(SSL *ssl, const void *buf, int num): the plaintext to send is in
// buf at entry. PARM1=ssl, PARM2=buf, PARM3=num.
SEC("uprobe/SSL_write")
int BPF_KPROBE(uprobe_ssl_write, void *ssl, void *buf, int num)
{
    if (!is_tls_target())
        return 0;
    emit_payload(TLS_DIR_WRITE, (__u64)(unsigned long)ssl, (__u64)(unsigned long)buf, num);
    return 0;
}

// SSL_read(SSL *ssl, void *buf, int num): buf is filled by the time SSL_read
// returns, so we stash {ssl, buf} at entry and read it in the uretprobe.
SEC("uprobe/SSL_read")
int BPF_KPROBE(uprobe_ssl_read, void *ssl, void *buf, int num)
{
    if (!is_tls_target())
        return 0;
    __u64 pt = bpf_get_current_pid_tgid();
    struct read_args ra = {
        .ssl = (__u64)(unsigned long)ssl,
        .buf = (__u64)(unsigned long)buf,
    };
    bpf_map_update_elem(&tls_read_args, &pt, &ra, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int BPF_KRETPROBE(uretprobe_ssl_read, int ret)
{
    __u64 pt = bpf_get_current_pid_tgid();
    struct read_args *ra = bpf_map_lookup_elem(&tls_read_args, &pt);
    if (!ra)
        return 0;
    __u64 ssl = ra->ssl;
    __u64 buf = ra->buf;
    bpf_map_delete_elem(&tls_read_args, &pt);
    emit_payload(TLS_DIR_READ, ssl, buf, ret);
    return 0;
}

// SSL_set_fd(SSL *ssl, int fd): remember the socket fd for connection
// correlation (no SSL-struct offsets needed — purely symbol-based).
SEC("uprobe/SSL_set_fd")
int BPF_KPROBE(uprobe_ssl_set_fd, void *ssl, int fd)
{
    if (!is_tls_target())
        return 0;
    __u64 key = (__u64)(unsigned long)ssl;
    __s32 v = fd;
    bpf_map_update_elem(&tls_ssl_fd, &key, &v, BPF_ANY);
    return 0;
}
