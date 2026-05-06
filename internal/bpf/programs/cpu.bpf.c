// SPDX-License-Identifier: GPL-2.0
//
// cpu.bpf.c — CPU sampling of the target PID via perf_event at 100Hz per CPU.
//
// Maps:
//   cpu_target_pid       ARRAY[1]  target pid (written by the Go loader)
//   cpu_target_samples   ARRAY[1]  accumulated counter of samples where the
//                                   target was on-CPU
//
// The Go loader opens a PERF_TYPE_SOFTWARE/PERF_COUNT_SW_CPU_CLOCK perf_event
// with sample_freq=100 on each CPU. Each time the kernel fires a sample,
// if the current tgid == target_pid, the counter is incremented.
//
// % computation on the Go side:
//   delta_samples / (sample_freq × elapsed_seconds × NCPU) × 100 = % of
//   the system. Multiply by NCPU to get % on a "single-core" scale (top-style).

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} cpu_target_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} cpu_target_samples SEC(".maps");

SEC("perf_event")
int handle_perf_event(void *ctx)
{
    __u32 key = 0;
    __u32 *target = bpf_map_lookup_elem(&cpu_target_pid, &key);
    if (!target || *target == 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);
    if (tgid != *target)
        return 0;

    __u64 *count = bpf_map_lookup_elem(&cpu_target_samples, &key);
    if (count)
        __sync_fetch_and_add(count, 1);
    return 0;
}
