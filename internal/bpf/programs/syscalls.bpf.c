// SPDX-License-Identifier: GPL-2.0
//
// syscalls.bpf.c — counts syscalls and measures latency per (enter, exit)
// raw_syscalls of the target PID.
//
// Maps:
//   target_pid     ARRAY[1]  struct target_filter (written by the Go loader)
//   syscall_count  HASH      syscall_id → {count, total_lat_ns}
//   enter_ts       HASH      tgid_pid → {ts_ns, arg0, syscall_id}
//                            correlates enter→exit to compute latency
//   restarting     LRU_HASH  tgid_pid → a call stopped by a signal that the
//                            kernel may re-run (restart.bpf.h, #160)
//   syscall_fdclass HASH     {syscall_id, fd class} → {count, total_lat_ns},
//                            for the read and write family only (#176)
//
// Compilation (run by `make gen` on Linux):
//   clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 \
//     -I/usr/include/bpf \
//     -c programs/syscalls.bpf.c -o programs/syscalls.bpf.o
//
// The Go loader (internal/bpf/syscalls.go) embeds the .o via go:embed and
// uses cilium/ebpf to load it, attach the tracepoints and read the
// syscall_count map.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <asm/unistd.h>
#include "target.bpf.h"
#include "restart.bpf.h"

char LICENSE[] SEC("license") = "GPL";

// raw_syscalls tracepoint structures — stable in the kernel since ~2010.
// Defining them inline avoids a dependency on vmlinux.h, which is large
// and arch-specific. The first u64 is padding for the tracepoint header
// (common_type/flag/preempt/pid).
struct sys_enter_args {
    unsigned long long _pad;
    long id;
    unsigned long args[6];
};

struct sys_exit_args {
    unsigned long long _pad;
    long id;
    long ret;
};

struct syscall_stat {
    __u64 count;
    __u64 total_lat_ns;
};

struct enter_data {
    __u64 ts_ns;
    __u64 arg0;       // a re-run enters with the same arguments
    __u32 syscall_id;
    __u32 fd_class;   // FD_CLASS_* for the read/write family, FD_CLASS_NONE otherwise
};

// A call stopped by a restart code, waiting to learn whether it is re-run.
struct restart_data {
    __u64 ts_ns;      // when it first entered
    __u64 end_ns;     // when it stopped: its end, if it returned EINTR
    __u64 arg0;
    __u32 syscall_id;
    __u32 fd_class;
};

// ─── The class of fd a read or write hit (#176) ─────────────────────────────
//
// `read` and `write` by name mix the application's I/O with the Go runtime's
// netpoller waking itself through an eventfd: measured on an I/O-free Go
// program, every read and write was on one anon_inode:[eventfd]. The class is
// the file's inode type, read once at entry: an anonymous inode (eventfd,
// epoll, timerfd, signalfd) has no type bits at all.
//
// The kernel structs are declared to the depth needed and relocated by CO-RE,
// the same way network.bpf.c reads a socket: no vmlinux.h.

#define FD_CLASS_NONE   0 // not in the read/write family: not classified
#define FD_CLASS_ANON   1 // anonymous inode: eventfd, epoll, timerfd, signalfd
#define FD_CLASS_SOCKET 2
#define FD_CLASS_PIPE   3
#define FD_CLASS_FILE   4 // regular file
#define FD_CLASS_CHAR   5 // character device (a tty, /dev/null)
#define FD_CLASS_OTHER  6 // a directory, a block device…
#define FD_CLASS_UNKNOWN 7 // the fd could not be read

#define PTOP_S_IFMT   0170000
#define PTOP_S_IFSOCK 0140000
#define PTOP_S_IFREG  0100000
#define PTOP_S_IFCHR  0020000
#define PTOP_S_IFIFO  0010000

struct inode___ptop {
    unsigned short i_mode;
} __attribute__((preserve_access_index));

struct file___ptop {
    struct inode___ptop *f_inode;
} __attribute__((preserve_access_index));

struct fdtable___ptop {
    unsigned int max_fds;
    struct file___ptop **fd;
} __attribute__((preserve_access_index));

struct files_struct___ptop {
    struct fdtable___ptop *fdt;
} __attribute__((preserve_access_index));

struct task_struct___ptop {
    struct files_struct___ptop *files;
} __attribute__((preserve_access_index));

static __always_inline int rw_family(__u32 id)
{
    switch (id) {
#ifdef __NR_read
    case __NR_read:
#endif
#ifdef __NR_write
    case __NR_write:
#endif
#ifdef __NR_readv
    case __NR_readv:
#endif
#ifdef __NR_writev
    case __NR_writev:
#endif
#ifdef __NR_pread64
    case __NR_pread64:
#endif
#ifdef __NR_pwrite64
    case __NR_pwrite64:
#endif
        return 1;
    default:
        return 0;
    }
}

static __always_inline __u32 fd_class(long fd)
{
    struct task_struct___ptop *task = (void *)bpf_get_current_task();
    struct files_struct___ptop *files = BPF_CORE_READ(task, files);
    if (!files)
        return FD_CLASS_UNKNOWN;
    struct fdtable___ptop *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt)
        return FD_CLASS_UNKNOWN;
    unsigned int max = BPF_CORE_READ(fdt, max_fds);
    if (fd < 0 || fd >= max)
        return FD_CLASS_UNKNOWN;
    struct file___ptop **fds = BPF_CORE_READ(fdt, fd);
    struct file___ptop *f = 0;
    if (bpf_probe_read_kernel(&f, sizeof(f), &fds[fd]) != 0 || !f)
        return FD_CLASS_UNKNOWN;
    unsigned short mode = BPF_CORE_READ(f, f_inode, i_mode);
    switch (mode & PTOP_S_IFMT) {
    case 0:
        return FD_CLASS_ANON;
    case PTOP_S_IFSOCK:
        return FD_CLASS_SOCKET;
    case PTOP_S_IFIFO:
        return FD_CLASS_PIPE;
    case PTOP_S_IFREG:
        return FD_CLASS_FILE;
    case PTOP_S_IFCHR:
        return FD_CLASS_CHAR;
    default:
        return FD_CLASS_OTHER;
    }
}

struct fdclass_key {
    __u32 syscall_id;
    __u32 fd_class;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct target_filter);
    __uint(max_entries, 1);
} target_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct syscall_stat);
    __uint(max_entries, 512);
} syscall_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct enter_data);
    __uint(max_entries, 10240);
} enter_ts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct fdclass_key);
    __type(value, struct syscall_stat);
    __uint(max_entries, 128);
} syscall_fdclass SEC(".maps");

// LRU: a thread killed inside the call never settles it.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);
    __type(value, struct restart_data);
    __uint(max_entries, 10240);
} restarting SEC(".maps");

// is_target returns 1 if the current task belongs to the target process,
// resolving pids inside the target's PID namespace (see target.bpf.h).
static __always_inline int is_target(void)
{
    return pid_is_target(&target_pid);
}

static __always_inline void account_class(__u32 sc_id, __u32 cls, __u64 lat_ns)
{
    if (cls == FD_CLASS_NONE)
        return;
    struct fdclass_key k = {.syscall_id = sc_id, .fd_class = cls};
    struct syscall_stat *stat = bpf_map_lookup_elem(&syscall_fdclass, &k);
    if (stat) {
        __sync_fetch_and_add(&stat->count, 1);
        __sync_fetch_and_add(&stat->total_lat_ns, lat_ns);
    } else {
        struct syscall_stat new_stat = {.count = 1, .total_lat_ns = lat_ns};
        bpf_map_update_elem(&syscall_fdclass, &k, &new_stat, BPF_ANY);
    }
}

static __always_inline void account(__u32 sc_id, __u64 lat_ns)
{
    struct syscall_stat *stat = bpf_map_lookup_elem(&syscall_count, &sc_id);
    if (stat) {
        __sync_fetch_and_add(&stat->count, 1);
        __sync_fetch_and_add(&stat->total_lat_ns, lat_ns);
    } else {
        struct syscall_stat new_stat = {.count = 1, .total_lat_ns = lat_ns};
        bpf_map_update_elem(&syscall_count, &sc_id, &new_stat, BPF_ANY);
    }
}

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct sys_enter_args *ctx)
{
    if (!is_target())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct enter_data data = {
        .ts_ns      = bpf_ktime_get_ns(),
        .arg0       = ctx->args[0],
        .syscall_id = (__u32)ctx->id,
    };
    if (rw_family(data.syscall_id))
        data.fd_class = fd_class((long)ctx->args[0]);
    // The kernel re-running a call a signal stopped: one call, timed from
    // its first entry (#160).
    struct restart_data *r = bpf_map_lookup_elem(&restarting, &pid_tgid);
    if (r && r->syscall_id == data.syscall_id && r->arg0 == data.arg0) {
        data.ts_ns = r->ts_ns;
        bpf_map_delete_elem(&restarting, &pid_tgid);
    }
    bpf_map_update_elem(&enter_ts, &pid_tgid, &data, BPF_ANY);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int handle_sys_exit(struct sys_exit_args *ctx)
{
    if (!is_target())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct enter_data *enter = bpf_map_lookup_elem(&enter_ts, &pid_tgid);
    if (!enter)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u32 sc_id = enter->syscall_id;
    __u32 cls = enter->fd_class;
    __u64 start = enter->ts_ns;
    if (ret_restarts(ctx->ret)) {
        // Not over yet, or over with EINTR: restart.bpf.h.
        struct restart_data r = {
            .ts_ns      = start,
            .end_ns     = now,
            .arg0       = enter->arg0,
            .syscall_id = sc_id,
            .fd_class   = cls,
        };
        bpf_map_update_elem(&restarting, &pid_tgid, &r, BPF_ANY);
        bpf_map_delete_elem(&enter_ts, &pid_tgid);
        return 0;
    }
    bpf_map_delete_elem(&enter_ts, &pid_tgid);

    // The id comes from the entry: rt_sigreturn exits with the id the frame
    // restored, -1 on x86 and arm64.
    if (sc_id == __NR_rt_sigreturn && ctx->ret == -PTOP_EINTR) {
        struct restart_data *r = bpf_map_lookup_elem(&restarting, &pid_tgid);
        if (r) {
            account(r->syscall_id, r->end_ns - r->ts_ns);
            account_class(r->syscall_id, r->fd_class, r->end_ns - r->ts_ns);
            bpf_map_delete_elem(&restarting, &pid_tgid);
        }
    }
    account(sc_id, now - start);
    account_class(sc_id, cls, now - start);
    return 0;
}
