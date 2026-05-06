// SPDX-License-Identifier: GPL-2.0
//
// threads.bpf.c — rastreia transições de scheduler (on-CPU ↔ off-CPU)
// das threads do PID alvo via tracepoint sched:sched_switch.
//
// Por que sched_switch e não /proc/<pid>/task/<tid>/stat?
//   /proc dá utime+stime cumulativos amostrados a 1Hz — granularidade
//   ruim pra threads que oscilam rápido entre running/blocked. O
//   tracepoint dispara em CADA context switch, então on_cpu_ns reflete
//   exatamente o que o kernel mediu, em tempo real.
//
// Maps:
//   threads_target_pid  ARRAY[1]  pid alvo (escrito pelo loader Go)
//   tracked_tids        HASH      TID → 1, populado periodicamente pelo
//                                 user-space (Go walks /proc/<pid>/task/).
//                                 Necessário porque sched_switch dispara
//                                 GLOBALMENTE — filtrar só pelo prev_pid
//                                 perderia o evento "next ON-CPU".
//   tid_state           HASH      TID → {last_on_ns, last_off_ns,
//                                 on_cpu_ns_total, off_cpu_ns_total,
//                                 ctx_switches}
//
// Filtragem:
//   Em vez de bpf_get_current_pid_tgid() (que é confiável em syscall
//   context, mas em sched_switch o `current` é o prev e nem sempre é o
//   alvo), usamos uma whitelist de TIDs (`tracked_tids`) atualizada
//   pelo Go side a cada ~1s. Threads que nascem/morrem dentro desse
//   intervalo podem perder switches; aceitável pra UI.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// Layout estável do tracepoint sched:sched_switch.
// /sys/kernel/debug/tracing/events/sched/sched_switch/format
struct sched_switch_args {
    unsigned long long _pad;     // common_type/flags/preempt_count/pid (8B)
    char prev_comm[16];          // offset 8
    int prev_pid;                // offset 24
    int prev_prio;               // offset 28
    long prev_state;             // offset 32
    char next_comm[16];          // offset 40
    int next_pid;                // offset 56
    int next_prio;               // offset 60
};

struct thread_state {
    __u64 last_on_cpu_ns;
    __u64 last_off_cpu_ns;
    __u64 on_cpu_ns_total;
    __u64 off_cpu_ns_total;
    __u64 ctx_switches;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} threads_target_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 8192);
} tracked_tids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct thread_state);
    __uint(max_entries, 8192);
} tid_state SEC(".maps");

static __always_inline int is_tracked(__u32 tid)
{
    return bpf_map_lookup_elem(&tracked_tids, &tid) != NULL;
}

// Pega-ou-cria entry no tid_state. Devolve ptr (sempre não-null em sucesso).
// Em falha de update (caso patológico), devolve NULL.
static __always_inline struct thread_state *get_or_create_state(__u32 tid)
{
    struct thread_state *s = bpf_map_lookup_elem(&tid_state, &tid);
    if (s)
        return s;
    struct thread_state zero = {};
    bpf_map_update_elem(&tid_state, &tid, &zero, BPF_ANY);
    return bpf_map_lookup_elem(&tid_state, &tid);
}

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct sched_switch_args *ctx)
{
    __u64 now = bpf_ktime_get_ns();

    // prev_pid está saindo de CPU
    __u32 prev_tid = (__u32)ctx->prev_pid;
    if (prev_tid != 0 && is_tracked(prev_tid)) {
        struct thread_state *s = get_or_create_state(prev_tid);
        if (s) {
            if (s->last_on_cpu_ns != 0) {
                __u64 delta = now - s->last_on_cpu_ns;
                __sync_fetch_and_add(&s->on_cpu_ns_total, delta);
            }
            s->last_off_cpu_ns = now;
            __sync_fetch_and_add(&s->ctx_switches, 1);
        }
    }

    // next_pid está entrando em CPU
    __u32 next_tid = (__u32)ctx->next_pid;
    if (next_tid != 0 && is_tracked(next_tid)) {
        struct thread_state *s = get_or_create_state(next_tid);
        if (s) {
            if (s->last_off_cpu_ns != 0) {
                __u64 delta = now - s->last_off_cpu_ns;
                __sync_fetch_and_add(&s->off_cpu_ns_total, delta);
            }
            s->last_on_cpu_ns = now;
        }
    }
    return 0;
}
