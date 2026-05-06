// SPDX-License-Identifier: GPL-2.0
//
// memory.bpf.c — counters de memória do PID alvo:
//
//   - kprobe handle_mm_fault          → page faults (cross-arch)
//   - tracepoint sys_enter_mmap       → mmap allocations
//   - tracepoint sys_enter_munmap     → munmap deallocations
//   - tracepoint sys_enter_brk        → heap growth (sbrk-style)
//
// Por que kprobe handle_mm_fault e não tracepoint exceptions:page_fault_user?
//   exceptions:page_fault_user é x86-only (vive em arch/x86/). handle_mm_fault
//   é a função canônica de mm/memory.c, existe em todas as arches Linux,
//   é chamada em process context e bpf_get_current_pid_tgid() funciona.
//   Trade-off: kprobe pode falhar se kernel tiver o símbolo inlined ou
//   renomeado (raro pra handle_mm_fault). Loader Go trata como warning.
//
// Maps:
//   mem_target_pid    ARRAY[1]  pid alvo (escrito pelo loader Go)
//   mem_counters      ARRAY[1]  struct {page_faults, mmaps, munmaps, brks}
//
// RSS NÃO é amostrado aqui — /proc/<pid>/statm é cheap e estável; eBPF
// pra RSS precisaria caminhar VMAs do mm_struct, mais caro e arch-frágil.

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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
    __type(value, __u32);
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
    __u32 key = 0;
    __u32 *target = bpf_map_lookup_elem(&mem_target_pid, &key);
    if (!target || *target == 0)
        return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);
    return tgid == *target;
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
