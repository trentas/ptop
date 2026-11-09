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
//   io_restarting       LRU_HASH   tgid_pid → a read/write stopped by a signal
//                                  that the kernel may re-run (restart.bpf.h,
//                                  #160)
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
// Why raw_syscalls/sys_{enter,exit} and not syscalls/sys_enter_<name> (#159):
//   on kernel 7.0 the per-syscall events for write, openat, unlinkat and
//   renameat* copy the user buffer or path into the event, and on that path the
//   BPF program never ran for calls made on any CPU but the first: measured,
//   20 of 20 writes and unlinks seen on CPU 0, 0 of 20 on CPU 1, every run.
//   read, whose event copies nothing, was seen on both. raw_syscalls carries
//   only the number and the six raw arguments, so nothing on its path reads
//   user memory, and the syscalls axis has counted exactly on every CPU through
//   it. The cost is that it fires for EVERY syscall on the host, so the number
//   is tested first and the target filter only after it.
//
//   The numbers come from the kernel's own <asm/unistd.h>, for the architecture
//   the object is compiled on (see "Build tags" in CLAUDE.md, #123). They are
//   the 64-bit native table: a 32-bit (compat) task numbers its syscalls from
//   another one, so the loader refuses a 32-bit target in pid mode (io.go).

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <asm/unistd.h>
#include "target.bpf.h"
#include "restart.bpf.h"

char LICENSE[] SEC("license") = "GPL";

// raw_syscalls/sys_exit layout: common header (8B), the syscall number, the
// return value. sys_enter's is struct sys_enter_args, below.
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
    __u64 end_ns; // in io_restarting: when the signal stopped it
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

// LRU: a thread killed inside the call never settles it.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);
    __type(value, struct io_inflight);
    __uint(max_entries, 10240);
} io_restarting SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB
} io_events SEC(".maps");

static __always_inline int is_io_target(void)
{
    return pid_is_target(&io_target_pid);
}

static __always_inline void emit_io(const struct io_inflight *inf, __u64 end, long ret, __u32 tgid)
{
    struct io_event *e = bpf_ringbuf_reserve(&io_events, sizeof(*e), 0);
    if (!e)
        return;
    e->ts_ns  = end;
    e->lat_ns = end - inf->ts_ns;
    e->bytes  = ret > 0 ? (__u64)ret : 0;
    e->fd     = inf->fd;
    e->op     = inf->op;
    e->tgid   = tgid;
    e->_pad   = 0;
    bpf_ringbuf_submit(e, 0);
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
    // The kernel re-running a read or write a signal stopped: one call, timed
    // from its first entry (#160).
    struct io_inflight *r = bpf_map_lookup_elem(&io_restarting, &pid_tgid);
    if (r && r->op == op && r->fd == fd && r->count_req == count) {
        inf.ts_ns = r->ts_ns;
        bpf_map_delete_elem(&io_restarting, &pid_tgid);
    }
    bpf_map_update_elem(&io_inflight_map, &pid_tgid, &inf, BPF_ANY);
}

static __always_inline void exit_io(long ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct io_inflight *inf = bpf_map_lookup_elem(&io_inflight_map, &pid_tgid);
    if (!inf)
        return;

    __u64 now = bpf_ktime_get_ns();
    if (ret_restarts(ret)) {
        // Not over yet, or over with EINTR: restart.bpf.h.
        struct io_inflight r = *inf;
        r.end_ns = now;
        bpf_map_update_elem(&io_restarting, &pid_tgid, &r, BPF_ANY);
    } else {
        emit_io(inf, now, ret, (__u32)(pid_tgid >> 32));
    }
    bpf_map_delete_elem(&io_inflight_map, &pid_tgid);
}

// sigreturn_io settles a stopped read or write when the handler that stopped
// it returns EINTR to it: the call ended at the exit already seen.
static __always_inline void sigreturn_io(long ret)
{
    if (ret != -PTOP_EINTR)
        return;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct io_inflight *r = bpf_map_lookup_elem(&io_restarting, &pid_tgid);
    if (!r)
        return;
    emit_io(r, r->end_ns, -PTOP_EINTR, (__u32)(pid_tgid >> 32));
    bpf_map_delete_elem(&io_restarting, &pid_tgid);
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

// raw_syscalls/sys_enter layout: common header (8B), the syscall number, and
// its six arguments as unsigned long — whatever the syscall, which is why one
// program can serve read, write and the fs-semantics calls alike.
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

// ─── dispatch ────────────────────────────────────────────────────────────────
//
// One pair for every syscall on the host (#159). The number is tested before
// anything else: almost no syscall is one of these, and almost none is the
// target's. The per-op argument positions:
//   read/write(fd, buf, count)                          fd args[0], count args[2]
//   open(path, …)                  unlink(path)         path args[0]
//   openat(dfd, path, …)           unlinkat(dfd, path, flag)   path args[1]
//   rename(old, new)                                    args[0], args[1]
//   renameat/renameat2(olddfd, old, newdfd, new, …)     args[1], args[3]
// Modern libcs route open/unlink/rename to the *at forms, and arm64 has none of
// the legacy three; they are matched where the architecture defines them.

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct sys_enter_args *ctx)
{
    switch (ctx->id) {
    case __NR_read:
        enter_io(OP_READ, (__u32)ctx->args[0], ctx->args[2]);
        break;
    case __NR_write:
        enter_io(OP_WRITE, (__u32)ctx->args[0], ctx->args[2]);
        break;
    case __NR_openat:
        fs_enter(FS_OP_OPEN_DENIED, ctx->args[1], 0);
        break;
    case __NR_unlinkat:
        fs_enter(FS_OP_UNLINK, ctx->args[1], 0);
        break;
    case __NR_renameat2:
        fs_enter(FS_OP_RENAME, ctx->args[1], ctx->args[3]);
        break;
#ifdef __NR_renameat
    case __NR_renameat:
        fs_enter(FS_OP_RENAME, ctx->args[1], ctx->args[3]);
        break;
#endif
#ifdef __NR_open
    case __NR_open:
        fs_enter(FS_OP_OPEN_DENIED, ctx->args[0], 0);
        break;
#endif
#ifdef __NR_unlink
    case __NR_unlink:
        fs_enter(FS_OP_UNLINK, ctx->args[0], 0);
        break;
#endif
#ifdef __NR_rename
    case __NR_rename:
        fs_enter(FS_OP_RENAME, ctx->args[0], ctx->args[1]);
        break;
#endif
    }
    return 0;
}

// The exits need no target filter of their own: only a target thread's enter
// stashed an in-flight entry, and the lookup is keyed by the thread.
SEC("tracepoint/raw_syscalls/sys_exit")
int handle_sys_exit(struct sys_exit_args *ctx)
{
    switch (ctx->id) {
    case __NR_read:
    case __NR_write:
        exit_io(ctx->ret);
        break;
    // rt_sigreturn's exit carries the id the restored frame holds, -1 on x86
    // and arm64 (restore_sigcontext forgets the syscall). Its return is the
    // restored register: -EINTR when the stopped call returns EINTR (#160).
    case -1:
    case __NR_rt_sigreturn:
        sigreturn_io(ctx->ret);
        break;
    case __NR_openat:
    case __NR_unlinkat:
    case __NR_renameat2:
#ifdef __NR_renameat
    case __NR_renameat:
#endif
#ifdef __NR_open
    case __NR_open:
#endif
#ifdef __NR_unlink
    case __NR_unlink:
#endif
#ifdef __NR_rename
    case __NR_rename:
#endif
        fs_exit(ctx->ret);
        break;
    }
    return 0;
}
