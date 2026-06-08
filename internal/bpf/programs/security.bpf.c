// SPDX-License-Identifier: GPL-2.0
//
// security.bpf.c — security-audit signals for the target PID (#59):
//
//   - runtime executable mappings: tracepoint sys_enter_mmap / sys_enter_mprotect
//     where prot includes PROT_EXEC (code mapped executable after start —
//     dlopen, JIT, or RWX injection), with the originating user call site.
//   - LSM decisions (best-effort): tracepoint avc/selinux_audited — SELinux
//     denials. Attached non-fatally; absent on non-SELinux kernels (the issue
//     allows graceful degradation).
//
// All three run in the target's PROCESS context, so the shared ns-aware
// pid_is_target() filter applies (like memory.bpf.c) — no global-pid handling.
//
// Maps:
//   sec_target_pid  ARRAY[1]      struct target_filter (written by the Go loader)
//   sec_events      RINGBUF       per-event channel → user-space
//   sec_stacks      STACK_TRACE   user stacks captured at the mapping call site

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "target.bpf.h"

char LICENSE[] SEC("license") = "GPL";

#define KIND_EXEC_MAP 0
#define KIND_LSM      1

#define OP_MMAP     0
#define OP_MPROTECT 1

#define PROT_EXEC      0x4
#define MAP_ANONYMOUS  0x20

#define SEC_STACK_DEPTH 32

// sys_enter_mmap: addr, len, prot, flags, fd, off (each a long after the
// 8-byte common header + the 8-byte __syscall_nr slot). Stable layout.
struct sys_enter_mmap_args {
    unsigned long long _pad;
    long id;
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long fd;
    unsigned long off;
};

// sys_enter_mprotect: addr, len, prot.
struct sys_enter_mprotect_args {
    unsigned long long _pad;
    long id;
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
};

// avc/selinux_audited (SELinux): requested/denied/audited perm masks + result,
// then __data_loc context strings (not read — see the collector). Numeric
// fields are the first after the common header and are reliable; the contexts +
// perm-name decoding are deferred (need per-class tables / a SELinux test host).
struct selinux_audited_args {
    unsigned long long _pad;
    __u32 requested;
    __u32 denied;
    __u32 audited;
    int result;
};

// sec_event is published via the sec_events ring buffer. Fixed 56-byte layout
// (multiple of 8 → Go-packed size == C sizeof) — keep in sync with SecurityRecord
// in internal/bpf/security.go.
struct sec_event {
    __u64 ts_ns;
    __u64 addr;          // exec-map mapping address; 0 for lsm
    __u64 len;           // exec-map mapping length; 0 for lsm
    __u32 kind;          // KIND_EXEC_MAP | KIND_LSM
    __u32 op;            // OP_MMAP | OP_MPROTECT (exec-map); 0 for lsm
    __u32 prot;          // PROT_* bitmask (exec-map); 0 for lsm
    __u32 flags;         // mmap flags (exec-map mmap only); 0 otherwise
    __u32 lsm_requested; // lsm: requested perm mask
    __u32 lsm_denied;    // lsm: denied perm mask
    __u32 lsm_audited;   // lsm: audited perm mask
    __s32 stack_id;      // exec-map user stack (<0 unknown); -1 for lsm
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct target_filter);
    __uint(max_entries, 1);
} sec_target_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); // 256KB — these events are low-rate
} sec_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, SEC_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, 4096);
} sec_stacks SEC(".maps");

static __always_inline int is_sec_target(void)
{
    return pid_is_target(&sec_target_pid);
}

// emit_exec_map publishes a PROT_EXEC mapping event, capturing the user call
// stack from ctx. ctx is void* so both tracepoint handlers can share it.
static __always_inline void emit_exec_map(void *ctx, __u32 op, __u64 addr,
                                          __u64 len, __u32 prot, __u32 flags)
{
    struct sec_event *e = bpf_ringbuf_reserve(&sec_events, sizeof(*e), 0);
    if (!e)
        return;
    __builtin_memset(e, 0, sizeof(*e));
    e->ts_ns = bpf_ktime_get_ns();
    e->kind = KIND_EXEC_MAP;
    e->op = op;
    e->addr = addr;
    e->len = len;
    e->prot = prot;
    e->flags = flags;
    e->stack_id = bpf_get_stackid(ctx, &sec_stacks, BPF_F_USER_STACK);
    bpf_ringbuf_submit(e, 0);
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int tp_sys_enter_mmap(struct sys_enter_mmap_args *ctx)
{
    if (!is_sec_target())
        return 0;
    if (!(ctx->prot & PROT_EXEC))
        return 0;
    emit_exec_map(ctx, OP_MMAP, ctx->addr, ctx->len,
                  (__u32)ctx->prot, (__u32)ctx->flags);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int tp_sys_enter_mprotect(struct sys_enter_mprotect_args *ctx)
{
    if (!is_sec_target())
        return 0;
    if (!(ctx->prot & PROT_EXEC))
        return 0;
    // mprotect changes an existing mapping; we can't tell anon from the args,
    // so flags=0 (the collector reports anon only for mmap).
    emit_exec_map(ctx, OP_MPROTECT, ctx->addr, ctx->len, (__u32)ctx->prot, 0);
    return 0;
}

SEC("tracepoint/avc/selinux_audited")
int tp_selinux_audited(struct selinux_audited_args *ctx)
{
    if (!is_sec_target())
        return 0;
    struct sec_event *e = bpf_ringbuf_reserve(&sec_events, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));
    e->ts_ns = bpf_ktime_get_ns();
    e->kind = KIND_LSM;
    e->lsm_requested = ctx->requested;
    e->lsm_denied = ctx->denied;
    e->lsm_audited = ctx->audited;
    e->stack_id = -1;
    bpf_ringbuf_submit(e, 0);
    return 0;
}
