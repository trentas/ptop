// SPDX-License-Identifier: GPL-2.0
//
// signal.bpf.c — captures signals DELIVERED TO the target process (#58) via the
// signal:signal_generate tracepoint, including WHO sent them.
//
//   tracepoint signal/signal_generate → {sig, target pid, si_code, result} and,
//   from the current task at fire time, the SENDER (pid + comm).
//
// Target filtering is unlike the other ptop programs. At signal_generate the
// "current task" is the SENDER (the task calling kill/tgkill, or — for
// kernel-generated signals like SIGSEGV/SIGPIPE — the target itself). The signal
// RECEIVER is the tracepoint's `pid` field, which is task->pid in the INITIAL
// pid namespace. bpf_get_ns_current_pid_tgid() can only project the *current*
// task (the sender here), not the target, so the shared pid_is_target() helper
// is wrong for this probe. Instead we filter ctx->pid against the target's
// GLOBAL pid, written into sig_target_pid by the Go loader (resolved from
// /proc/<pid>/status NSpid). Documented caveat: under a nested pid namespace the
// global pid is used, so the receiver filter is exact only when the loader could
// resolve it (it always can on a normal host where ns-local == global).
//
// Maps:
//   sig_target_pid  ARRAY[1]  __u32 — target's global (init-ns) pid
//   sig_events      RINGBUF   per-signal channel → user-space

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// Layout of the signal:signal_generate tracepoint (stable). After the 8-byte
// common header: sig, errno, code, comm[16], pid (the RECEIVER, task->pid),
// group, result. Offsets are natural (no padding needed).
struct signal_generate_args {
    unsigned long long _pad; // common_type/flags/preempt_count/pid (8 bytes)
    int sig;                 // signal number
    int err;                 // si_errno (kernel field name "errno")
    int code;                // si_code (SI_USER/SI_KERNEL/…) — root-cause hint
    char comm[16];           // target task->comm
    int pid;                 // RECEIVER pid (task->pid, initial ns)
    int group;               // group-directed (1) vs thread-directed (0)
    int result;              // TRACE_SIGNAL_* (delivered/ignored/blocked/…)
};

// sig_event is published via the sig_events ring buffer. Fixed layout (56 bytes),
// read with binary.LittleEndian on the Go side — keep in sync with SignalRecord
// in internal/bpf/signal.go.
struct sig_event {
    __u64 ts_ns;
    __u32 signo;
    __u32 sender_pid;  // sending process (current tgid)
    __u32 sender_tid;  // sending thread (current pid) — kept for alignment
    __u32 target_tid;  // receiver pid (ctx->pid)
    __s32 code;        // si_code
    __s32 err;         // si_errno
    __u32 result;      // TRACE_SIGNAL_*
    __u32 group;       // group- vs thread-directed
    char  sender_comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32); // target's global (init-ns) pid
    __uint(max_entries, 1);
} sig_target_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); // 256KB — signals are low-rate
} sig_events SEC(".maps");

SEC("tracepoint/signal/signal_generate")
int handle_signal_generate(struct signal_generate_args *ctx)
{
    __u32 key = 0;
    __u32 *target = bpf_map_lookup_elem(&sig_target_pid, &key);
    if (!target || *target == 0)
        return 0;
    // Filter: only signals whose RECEIVER is our target process.
    if ((__u32)ctx->pid != *target)
        return 0;

    struct sig_event *e = bpf_ringbuf_reserve(&sig_events, sizeof(*e), 0);
    if (!e)
        return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid(); // the SENDER (current task)
    e->ts_ns      = bpf_ktime_get_ns();
    e->signo      = (__u32)ctx->sig;
    e->sender_pid = (__u32)(pid_tgid >> 32);
    e->sender_tid = (__u32)pid_tgid;
    e->target_tid = (__u32)ctx->pid;
    e->code       = ctx->code;
    e->err        = ctx->err;
    e->result     = (__u32)ctx->result;
    e->group      = (__u32)ctx->group;
    bpf_get_current_comm(e->sender_comm, sizeof(e->sender_comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
