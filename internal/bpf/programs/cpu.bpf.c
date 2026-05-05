// SPDX-License-Identifier: GPL-2.0
//
// cpu.bpf.c — sampling de CPU do PID alvo via perf_event a 100Hz por CPU.
//
// Maps:
//   cpu_target_pid       ARRAY[1]  pid alvo (escrito pelo loader Go)
//   cpu_target_samples   ARRAY[1]  contador acumulado de samples onde o
//                                   target estava on-CPU
//
// Loader Go abre um perf_event PERF_TYPE_SOFTWARE/PERF_COUNT_SW_CPU_CLOCK
// com sample_freq=100 em cada CPU. Cada vez que o kernel dispara um sample,
// se o tgid atual == target_pid, incrementa o contador.
//
// Cálculo do % no Go side:
//   delta_samples / (sample_freq × elapsed_seconds × NCPU) × 100 = % do
//   sistema. Multiplica por NCPU pra ter % em escala "single-core" (top-style).

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
