// SPDX-License-Identifier: GPL-2.0
//
// syscalls.bpf.c — conta syscalls e mede latência por (enter, exit)
// raw_syscalls do PID alvo.
//
// Maps:
//   target_pid     ARRAY[1]  pid alvo (escrito pelo loader Go via map.Update)
//   syscall_count  HASH      syscall_id → {count, total_lat_ns}
//   enter_ts       HASH      tgid_pid → {ts_ns, syscall_id}
//                            correlaciona enter→exit pra calcular latência
//
// Compilação (rodada por `make gen` em Linux):
//   clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 \
//     -I/usr/include/bpf \
//     -c programs/syscalls.bpf.c -o programs/syscalls.bpf.o
//
// O loader Go (internal/bpf/syscalls.go) embute o .o via go:embed e usa
// cilium/ebpf pra carregar, attachar tracepoints e ler o map syscall_count.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// Estruturas dos tracepoints raw_syscalls — estáveis no kernel desde ~2010.
// Definir inline evita dependência de vmlinux.h, que é grande e arch-específico.
// O primeiro u64 é padding pro tracepoint header (common_type/flag/preempt/pid).
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
    __u32 syscall_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
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

// is_target retorna 1 se o tgid atual é o pid alvo configurado, 0 caso contrário.
static __always_inline int is_target(void)
{
    __u32 key = 0;
    __u32 *target = bpf_map_lookup_elem(&target_pid, &key);
    if (!target || *target == 0)
        return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);
    return tgid == *target;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct sys_enter_args *ctx)
{
    if (!is_target())
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct enter_data data = {
        .ts_ns      = bpf_ktime_get_ns(),
        .syscall_id = (__u32)ctx->id,
    };
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

    __u64 lat_ns = bpf_ktime_get_ns() - enter->ts_ns;
    __u32 sc_id = enter->syscall_id;
    bpf_map_delete_elem(&enter_ts, &pid_tgid);

    struct syscall_stat *stat = bpf_map_lookup_elem(&syscall_count, &sc_id);
    if (stat) {
        __sync_fetch_and_add(&stat->count, 1);
        __sync_fetch_and_add(&stat->total_lat_ns, lat_ns);
    } else {
        struct syscall_stat new_stat = {.count = 1, .total_lat_ns = lat_ns};
        bpf_map_update_elem(&syscall_count, &sc_id, &new_stat, BPF_ANY);
    }
    return 0;
}
