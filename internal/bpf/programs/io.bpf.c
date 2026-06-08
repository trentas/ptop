// SPDX-License-Identifier: GPL-2.0
//
// io.bpf.c — traces synchronous I/O syscalls (read/write) of the target PID,
// measures per-call latency, AND captures filesystem *semantics* (#57):
// permission denials (open/openat → EACCES/EPERM), deletes (unlink/unlinkat),
// and renames (rename/renameat2) with their real paths. Both rides the same
// process-context target filter (is_io_target) but uses separate maps + a
// separate ring buffer so the fs-event path is independent of the throughput
// path. Events are emitted via ring buffers.
//
// Maps:
//   io_target_pid       ARRAY[1]   struct target_filter (written by the Go loader)
//   io_inflight_map     HASH       tgid_pid → {ts_ns, fd, op, count_req}
//                                  tracks an in-flight read/write to correlate
//                                  enter/exit
//   io_events           RINGBUF    throughput channel — fd, op, bytes, latency
//   fs_inflight_map     HASH       tgid_pid → {op, path ptr, newpath ptr} (#57)
//   fs_events           RINGBUF    fs-semantics channel — op, ret, path(s) (#57)
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
// pkg/collector/io_ebpf.go.
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

// ─── #57 filesystem semantics: permission denials, deletes, renames ───────────
//
// These syscalls run in process context, so they reuse is_io_target(). We stash
// the user-space path pointer(s) at sys_enter and read the string at sys_exit
// (where the return value — hence EACCES/EPERM — is known). The user path buffer
// is still mapped at exit (same task), so reading the pointer there is valid —
// the proven libbpf-tools opensnoop approach, which avoids carrying a large
// string through the inflight map.

#define FS_OP_OPEN_DENIED 0 // open/openat returned EACCES/EPERM
#define FS_OP_UNLINK      1 // unlink/unlinkat
#define FS_OP_RENAME      2 // rename/renameat/renameat2

#define EACCES 13
#define EPERM  1

#define FS_PATH_MAX 256

// Generic sys_enter layout: common header (8B) + syscall nr (widened to 8B) +
// up to 6 args, each widened to unsigned long in the tracepoint record (the
// same widening the read/write sys_enter_rw_args above relies on).
struct sys_enter_args {
    unsigned long long _pad;
    long id;
    unsigned long args[6];
};

// fs_inflight stashes the user path pointer(s) between sys_enter and sys_exit.
// Keyed by pid_tgid — a thread is in exactly one syscall at a time, so no
// overwrite races. Tiny value (pointers only); the string is read at exit.
struct fs_inflight {
    __u32 op;
    __u64 path;    // const char __user *
    __u64 newpath; // const char __user * (RENAME); 0 otherwise
};

// fs_event is published to user-space via the fs_events ring buffer. Fixed
// layout (536 bytes), read with binary.LittleEndian on the Go side — keep in
// sync with FSEventRecord in internal/bpf/io.go.
struct fs_event {
    __u64 ts_ns;
    __u32 tgid;
    __s32 ret; // syscall return: negative errno on failure, >=0 on success
    __u32 op;  // FS_OP_*
    __u32 _pad;
    char  path[FS_PATH_MAX];
    char  newpath[FS_PATH_MAX]; // RENAME destination; "" otherwise
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct fs_inflight);
    __uint(max_entries, 10240);
} fs_inflight_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 19); // 512KB — fs events are low-rate
} fs_events SEC(".maps");

static __always_inline void fs_enter(__u32 op, __u64 path, __u64 newpath)
{
    if (!is_io_target())
        return;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct fs_inflight inf = {
        .op      = op,
        .path    = path,
        .newpath = newpath,
    };
    bpf_map_update_elem(&fs_inflight_map, &pid_tgid, &inf, BPF_ANY);
}

// fs_exit publishes the event when warranted. For OPEN we only surface denials
// (EACCES/EPERM); unlink/rename always publish — a failed delete/rename is still
// notable — carrying the errno in ret. The inflight lookup is itself the target
// filter (only target threads ever stash an entry), so no is_io_target() here.
static __always_inline void fs_exit(long ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct fs_inflight *inf = bpf_map_lookup_elem(&fs_inflight_map, &pid_tgid);
    if (!inf)
        return;
    __u32 op = inf->op;
    __u64 path = inf->path;
    __u64 newpath = inf->newpath;
    bpf_map_delete_elem(&fs_inflight_map, &pid_tgid);

    if (op == FS_OP_OPEN_DENIED && ret != -EACCES && ret != -EPERM)
        return;

    struct fs_event *e = bpf_ringbuf_reserve(&fs_events, sizeof(*e), 0);
    if (!e)
        return;
    e->ts_ns      = bpf_ktime_get_ns();
    e->tgid       = (__u32)(pid_tgid >> 32);
    e->ret        = (__s32)ret;
    e->op         = op;
    e->_pad       = 0;
    e->path[0]    = '\0';
    e->newpath[0] = '\0';
    if (path)
        bpf_probe_read_user_str(e->path, sizeof(e->path), (const void *)path);
    if (newpath)
        bpf_probe_read_user_str(e->newpath, sizeof(e->newpath), (const void *)newpath);
    bpf_ringbuf_submit(e, 0);
}

// open(filename, …) → args[0]; openat(dfd, filename, …) → args[1]. Modern glibc
// routes open()→openat, and arm64 has no open/unlink/rename — the Go loader
// attaches the legacy variants non-fatally for raw-syscall callers on x86_64.
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_enter_openat(struct sys_enter_args *ctx)
{
    fs_enter(FS_OP_OPEN_DENIED, ctx->args[1], 0);
    return 0;
}
SEC("tracepoint/syscalls/sys_exit_openat")
int handle_exit_openat(struct sys_exit_args *ctx)
{
    fs_exit(ctx->ret);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int handle_enter_open(struct sys_enter_args *ctx)
{
    fs_enter(FS_OP_OPEN_DENIED, ctx->args[0], 0);
    return 0;
}
SEC("tracepoint/syscalls/sys_exit_open")
int handle_exit_open(struct sys_exit_args *ctx)
{
    fs_exit(ctx->ret);
    return 0;
}

// unlink(pathname) → args[0]; unlinkat(dfd, pathname, flag) → args[1].
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_enter_unlinkat(struct sys_enter_args *ctx)
{
    fs_enter(FS_OP_UNLINK, ctx->args[1], 0);
    return 0;
}
SEC("tracepoint/syscalls/sys_exit_unlinkat")
int handle_exit_unlinkat(struct sys_exit_args *ctx)
{
    fs_exit(ctx->ret);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int handle_enter_unlink(struct sys_enter_args *ctx)
{
    fs_enter(FS_OP_UNLINK, ctx->args[0], 0);
    return 0;
}
SEC("tracepoint/syscalls/sys_exit_unlink")
int handle_exit_unlink(struct sys_exit_args *ctx)
{
    fs_exit(ctx->ret);
    return 0;
}

// rename(old, new) → args[0],args[1]; renameat/renameat2(olddfd, old, newdfd,
// new, …) → args[1],args[3].
SEC("tracepoint/syscalls/sys_enter_renameat2")
int handle_enter_renameat2(struct sys_enter_args *ctx)
{
    fs_enter(FS_OP_RENAME, ctx->args[1], ctx->args[3]);
    return 0;
}
SEC("tracepoint/syscalls/sys_exit_renameat2")
int handle_exit_renameat2(struct sys_exit_args *ctx)
{
    fs_exit(ctx->ret);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int handle_enter_renameat(struct sys_enter_args *ctx)
{
    fs_enter(FS_OP_RENAME, ctx->args[1], ctx->args[3]);
    return 0;
}
SEC("tracepoint/syscalls/sys_exit_renameat")
int handle_exit_renameat(struct sys_exit_args *ctx)
{
    fs_exit(ctx->ret);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rename")
int handle_enter_rename(struct sys_enter_args *ctx)
{
    fs_enter(FS_OP_RENAME, ctx->args[0], ctx->args[1]);
    return 0;
}
SEC("tracepoint/syscalls/sys_exit_rename")
int handle_exit_rename(struct sys_exit_args *ctx)
{
    fs_exit(ctx->ret);
    return 0;
}
