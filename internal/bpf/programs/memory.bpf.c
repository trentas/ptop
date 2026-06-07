// SPDX-License-Identifier: GPL-2.0
//
// memory.bpf.c — memory counters for the target PID:
//
//   - kprobe handle_mm_fault          → page faults (cross-arch)
//   - tracepoint sys_enter_mmap       → mmap allocations
//   - tracepoint sys_enter_munmap     → munmap deallocations
//   - tracepoint sys_enter_brk        → heap growth (sbrk-style)
//
// Why kprobe handle_mm_fault and not the exceptions:page_fault_user tracepoint?
//   exceptions:page_fault_user is x86-only (lives in arch/x86/). handle_mm_fault
//   is the canonical function in mm/memory.c, exists on every Linux arch, is
//   called in process context where the pid filter works.
//   Trade-off: the kprobe can fail if the kernel has the symbol inlined or
//   renamed (rare for handle_mm_fault). The Go loader treats it as a warning.
//
// Maps:
//   mem_target_pid    ARRAY[1]  struct target_filter (written by the Go loader)
//   mem_counters      ARRAY[1]  struct {page_faults, mmaps, munmaps, brks}
//
// RSS is NOT sampled here — /proc/<pid>/statm is cheap and stable; doing RSS
// via eBPF would require walking the mm_struct's VMAs, more expensive and
// arch-fragile.

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "target.bpf.h"

char LICENSE[] SEC("license") = "GPL";

struct mem_counters {
    __u64 page_faults;
    __u64 mmap_count;
    __u64 munmap_count;
    __u64 brk_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct target_filter);
    __uint(max_entries, 1);
} mem_target_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct mem_counters);
    __uint(max_entries, 1);
} mem_counters SEC(".maps");

static __always_inline int is_mem_target(void)
{
    return pid_is_target(&mem_target_pid);
}

static __always_inline struct mem_counters *get_counters(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&mem_counters, &zero);
}

SEC("kprobe/handle_mm_fault")
int BPF_KPROBE(kp_handle_mm_fault)
{
    if (!is_mem_target())
        return 0;
    struct mem_counters *c = get_counters();
    if (c)
        __sync_fetch_and_add(&c->page_faults, 1);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int tp_sys_enter_mmap(void *ctx)
{
    if (!is_mem_target())
        return 0;
    struct mem_counters *c = get_counters();
    if (c)
        __sync_fetch_and_add(&c->mmap_count, 1);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_munmap")
int tp_sys_enter_munmap(void *ctx)
{
    if (!is_mem_target())
        return 0;
    struct mem_counters *c = get_counters();
    if (c)
        __sync_fetch_and_add(&c->munmap_count, 1);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_brk")
int tp_sys_enter_brk(void *ctx)
{
    if (!is_mem_target())
        return 0;
    struct mem_counters *c = get_counters();
    if (c)
        __sync_fetch_and_add(&c->brk_count, 1);
    return 0;
}
