// SPDX-License-Identifier: GPL-2.0
//
// syscalls.bpf.c — rastreia syscalls de um processo específico
//
// Compilar com:
//   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
//     -I/usr/include/bpf \
//     -c syscalls.bpf.c -o syscalls.bpf.o
//
// O Go loader em internal/bpf/loader.go embute o .o via go:embed
// e usa libbpfgo para carregar, filtrar por PID e ler os maps.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// PID a monitorar — preenchido pelo loader Go via bpf_map_update_elem
struct {
    __uint(type,  BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u32);
} target_pid SEC(".maps");

// Contagem de syscalls por número
struct {
    __uint(type,  BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key,   __u32);   // syscall number
    __type(value, __u64);   // count
} syscall_counts SEC(".maps");

// Ring buffer para eventos individuais (latência, args)
struct syscall_event {
    __u32 pid;
    __u32 syscall_nr;
    __u64 ts_enter;
    __u64 ts_exit;
    char  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB
} syscall_events SEC(".maps");

// Timestamp de entrada por TID (para calcular latência no exit)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key,   __u32);  // tid
    __type(value, __u64);  // timestamp ns
} enter_ts SEC(".maps");

static __always_inline int is_target_pid(__u32 pid) {
    __u32 key = 0;
    __u32 *tpid = bpf_map_lookup_elem(&target_pid, &key);
    if (!tpid || *tpid == 0) return 0;
    return pid == *tpid;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!is_target_pid(pid)) return 0;

    __u32 tid = (__u32)pid_tgid;
    __u64 ts  = bpf_ktime_get_ns();
    bpf_map_update_elem(&enter_ts, &tid, &ts, BPF_ANY);

    __u32 nr = (__u32)ctx->id;
    __u64 *count = bpf_map_lookup_elem(&syscall_counts, &nr);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&syscall_counts, &nr, &one, BPF_ANY);
    }

    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int tracepoint__raw_syscalls__sys_exit(struct trace_event_raw_sys_exit *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!is_target_pid(pid)) return 0;

    __u32 tid = (__u32)pid_tgid;
    __u64 *enter = bpf_map_lookup_elem(&enter_ts, &tid);
    if (!enter) return 0;

    struct syscall_event *e = bpf_ringbuf_reserve(&syscall_events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid        = pid;
    e->syscall_nr = (__u32)ctx->id;
    e->ts_enter   = *enter;
    e->ts_exit    = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&enter_ts, &tid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
