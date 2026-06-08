// SPDX-License-Identifier: GPL-2.0
//
// proc.bpf.c — exec lineage (#60): reconstructs the process tree the target
// spawns via the scheduler's fork/exec/exit tracepoints.
//
//   sched/sched_process_fork  → a fork/clone (parent_pid → child_pid)
//   sched/sched_process_exec  → an execve (pid + the executed filename)
//   sched/sched_process_exit  → a task exit (pid)
//
// Target filtering — like signal.bpf.c (#58), NOT like the per-subsystem
// programs. These tracepoints report task pids in the INITIAL (global) pid
// namespace, and at fork/exec/exit the relevant task is not necessarily the
// "current" task in a projectable way, so bpf_get_ns_current_pid_tgid() /
// pid_is_target() don't apply. Instead we keep a `proc_tracked` set of GLOBAL
// pids, seeded by the Go loader with the target's global pid (from
// /proc/<pid>/status NSpid) and grown on every fork whose PARENT is tracked —
// so the whole descendant subtree is captured. A tracked pid is removed on its
// exit.
//
// Threads vs processes: sched_process_fork fires for clone(CLONE_THREAD) too, so
// "fork" events include thread creation and the tracked set holds thread pids as
// well as process pids. That is deliberate — it both matches the issue's
// "execve / clone / fork" wording and makes the subtree filter robust (a child
// forked by a worker thread of the target is still attributed, because the
// worker thread's pid is tracked). Consumers that want only processes can filter
// on pid==tgid downstream.
//
// Attach-time limitation: only forks observed AFTER attach populate the set, so
// pre-existing children/threads of the target aren't tracked until they fork
// again. Same caveat as every other ptop eBPF collector.
//
// Maps:
//   proc_tracked  HASH      __u32 global pid → __u8 (seeded with the target)
//   proc_events   RINGBUF   per-event channel → user-space

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define PROC_FORK 0
#define PROC_EXEC 1
#define PROC_EXIT 2

#define COMM_LEN 16
#define FILENAME_LEN 128

// Tracepoint layouts, hand-laid from the stable `format` files (offsets after
// the 8-byte common header common_type/flags/preempt_count/pid).
//
// sched/sched_process_fork: parent_comm[16]@8, parent_pid@24, child_comm[16]@28,
// child_pid@44.
struct sched_process_fork_args {
    unsigned long long _pad;
    char parent_comm[COMM_LEN];
    int parent_pid;
    char child_comm[COMM_LEN];
    int child_pid;
};

// sched/sched_process_exec: __data_loc filename@8 (u32: low16 offset, high16
// len), pid@12, old_pid@16.
struct sched_process_exec_args {
    unsigned long long _pad;
    unsigned int filename; // __data_loc
    int pid;
    int old_pid;
};

// sched/sched_process_exit: comm[16]@8, pid@24, prio@28.
struct sched_process_exit_args {
    unsigned long long _pad;
    char comm[COMM_LEN];
    int pid;
    int prio;
};

// proc_event is published via the proc_events ring buffer. Fixed 168-byte layout
// (the _pad makes the Go-side packed size equal C's sizeof) — keep in sync with
// ProcRecord in internal/bpf/proc.go.
struct proc_event {
    __u64 ts_ns;
    __u32 kind; // PROC_FORK | PROC_EXEC | PROC_EXIT
    __s32 pid;  // subject: child for fork, the task itself for exec/exit
    __s32 ppid; // parent (fork only; 0 otherwise)
    __u32 _pad;
    char comm[COMM_LEN];
    char filename[FILENAME_LEN]; // exec only; "" otherwise
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // global pid
    __type(value, __u8); // present == tracked
    __uint(max_entries, 4096);
} proc_tracked SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); // 256KB — lifecycle events are low-rate
} proc_events SEC(".maps");

static __always_inline int is_tracked(__u32 pid)
{
    return bpf_map_lookup_elem(&proc_tracked, &pid) != 0;
}

SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct sched_process_fork_args *ctx)
{
    __u32 ppid = (__u32)ctx->parent_pid;
    if (!is_tracked(ppid))
        return 0;

    // The child (process or thread) is a descendant — track it so its own
    // forks are attributed too.
    __u32 child = (__u32)ctx->child_pid;
    __u8 one = 1;
    bpf_map_update_elem(&proc_tracked, &child, &one, BPF_ANY);

    struct proc_event *e = bpf_ringbuf_reserve(&proc_events, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));
    e->ts_ns = bpf_ktime_get_ns();
    e->kind = PROC_FORK;
    e->pid = ctx->child_pid;
    e->ppid = ctx->parent_pid;
    __builtin_memcpy(e->comm, ctx->child_comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct sched_process_exec_args *ctx)
{
    __u32 pid = (__u32)ctx->pid;
    if (!is_tracked(pid))
        return 0;

    struct proc_event *e = bpf_ringbuf_reserve(&proc_events, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));
    e->ts_ns = bpf_ktime_get_ns();
    e->kind = PROC_EXEC;
    e->pid = ctx->pid;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    // Read the executed path from the tracepoint's __data_loc field: the low 16
    // bits are the byte offset of the string within the record (relative to
    // ctx). The size is the CONSTANT sizeof(filename), so the verifier accepts
    // the read directly (no variable-length mask needed).
    unsigned short off = (unsigned short)(ctx->filename & 0xFFFF);
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), (void *)ctx + off);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct sched_process_exit_args *ctx)
{
    __u32 pid = (__u32)ctx->pid;
    if (!is_tracked(pid))
        return 0;

    struct proc_event *e = bpf_ringbuf_reserve(&proc_events, sizeof(*e), 0);
    if (!e) {
        // Still drop it from the set so the map doesn't leak dead pids.
        bpf_map_delete_elem(&proc_tracked, &pid);
        return 0;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->ts_ns = bpf_ktime_get_ns();
    e->kind = PROC_EXIT;
    e->pid = ctx->pid;
    __builtin_memcpy(e->comm, ctx->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);

    bpf_map_delete_elem(&proc_tracked, &pid);
    return 0;
}
