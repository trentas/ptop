// SPDX-License-Identifier: GPL-2.0
//
// io.bpf.c — traces synchronous I/O syscalls (read/write/pread64/pwrite64)
// of the target PID, measures per-call latency and emits events via ring buffer.
//
// Maps:
//   io_target_pid       ARRAY[1]   struct target_filter (written by the Go loader)
//   io_inflight_map     HASH       tgid_pid → {ts_ns, fd, op, count_req}
//                                  tracks an in-flight syscall to correlate
//                                  enter/exit
//   io_events           RINGBUF    channel to user-space — each event contains
//                                  fd, op type, bytes read/written, latency
//
// Why syscall-level (not block-level)?
//   block:block_rq_* gives REAL disk latency (excludes cache). But resolving
//   the file path requires vmlinux.h or CO-RE. Here we use sys_enter_/sys_exit_
//   tracepoints that give the fd directly — Go resolves fd→path via
//   /proc/<pid>/fd. Trade-off: we show syscall-level I/O (includes cache hits),
//   which is what the user sees in "files accessed" and matches the F5 mockup.
//
// syscalls/sys_enter_X tracepoints are arch-independent (the kernel resolves
// by name, not by number) — code compiled on x86_64 works on arm64.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "target.bpf.h"

char LICENSE[] SEC("license") = "GPL";

// Tracepoint structures. Stable layout from
// /sys/kernel/debug/tracing/events/syscalls/sys_enter_read/format:
//
//   common_type/flags/preempt_count/pid    (8 bytes)
//   __syscall_nr int + padding              (8 bytes)
//   fd unsigned long                        (8 bytes)
//   buf char*                               (8 bytes)
//   count size_t                            (8 bytes)
struct sys_enter_rw_args {
    unsigned long long _pad;
    long id;
    unsigned long fd;
    unsigned long buf;
    unsigned long count;
};

struct sys_exit_args {
    unsigned long long _pad;
    long id;
    long ret;
};

// Op codes — must match the Go side (collector/io_ebpf.go).
#define OP_READ  0
#define OP_WRITE 1

struct io_inflight {
    __u64 ts_ns;
    __u32 fd;
    __u32 op;
    __u64 count_req;
};

// Event published to user-space via ring buffer. Fixed layout, read with
// binary.LittleEndian on the Go side. Keep in sync with IOEvent in
// internal/collector/io_ebpf.go.
struct io_event {
    __u64 ts_ns;
    __u64 lat_ns;
    __u64 bytes;       // ret value (when positive)
    __u32 fd;
    __u32 op;
    __u32 tgid;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct target_filter);
    __uint(max_entries, 1);
} io_target_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct io_inflight);
    __uint(max_entries, 10240);
} io_inflight_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB
} io_events SEC(".maps");

static __always_inline int is_io_target(void)
{
    return pid_is_target(&io_target_pid);
}

static __always_inline void enter_io(__u32 op, __u32 fd, __u64 count)
{
    if (!is_io_target())
        return;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct io_inflight inf = {
        .ts_ns     = bpf_ktime_get_ns(),
        .fd        = fd,
        .op        = op,
        .count_req = count,
    };
    bpf_map_update_elem(&io_inflight_map, &pid_tgid, &inf, BPF_ANY);
}

static __always_inline void exit_io(long ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct io_inflight *inf = bpf_map_lookup_elem(&io_inflight_map, &pid_tgid);
    if (!inf)
        return;

    struct io_event *e = bpf_ringbuf_reserve(&io_events, sizeof(*e), 0);
    if (e) {
        __u64 now = bpf_ktime_get_ns();
        e->ts_ns  = now;
        e->lat_ns = now - inf->ts_ns;
        e->bytes  = ret > 0 ? (__u64)ret : 0;
        e->fd     = inf->fd;
        e->op     = inf->op;
        e->tgid   = (__u32)(pid_tgid >> 32);
        e->_pad   = 0;
        bpf_ringbuf_submit(e, 0);
    }
    bpf_map_delete_elem(&io_inflight_map, &pid_tgid);
}

SEC("tracepoint/syscalls/sys_enter_read")
int handle_enter_read(struct sys_enter_rw_args *ctx)
{
    enter_io(OP_READ, (__u32)ctx->fd, ctx->count);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int handle_exit_read(struct sys_exit_args *ctx)
{
    if (!is_io_target())
        return 0;
    exit_io(ctx->ret);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int handle_enter_write(struct sys_enter_rw_args *ctx)
{
    enter_io(OP_WRITE, (__u32)ctx->fd, ctx->count);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int handle_exit_write(struct sys_exit_args *ctx)
{
    if (!is_io_target())
        return 0;
    exit_io(ctx->ret);
    return 0;
}
