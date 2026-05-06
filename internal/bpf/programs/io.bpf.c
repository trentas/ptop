// SPDX-License-Identifier: GPL-2.0
//
// io.bpf.c — rastreia syscalls de I/O síncrono (read/write/pread64/pwrite64)
// do PID alvo, mede latência por chamada e emite eventos via ring buffer.
//
// Maps:
//   io_target_pid       ARRAY[1]   pid alvo (escrito pelo loader Go)
//   io_inflight_map     HASH       tgid_pid → {ts_ns, fd, op, count_req}
//                                  rastreia syscall em flight pra correlacionar
//                                  enter/exit
//   io_events           RINGBUF    canal pro user-space — cada evento contém
//                                  fd, op type, bytes lidos/escritos, latência
//
// Por que syscall-level (não block-level)?
//   block:block_rq_* dá latência REAL de disco (exclui cache). Mas resolver
//   path do file requer vmlinux.h ou CO-RE. Aqui usamos sys_enter_/sys_exit_
//   tracepoints que dão fd direto — Go resolve fd→path via /proc/<pid>/fd.
//   Trade-off: mostramos I/O syscall-level (inclui cache hits), que é o que
//   o usuário vê em "files acessados" e bate com o mockup de F5.
//
// Tracepoints em syscalls/sys_enter_X são arch-independentes (kernel resolve
// pelo nome, não pelo número) — código compilado em x86_64 funciona em arm64.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// Estruturas dos tracepoints. Layout estável de
// /sys/kernel/debug/tracing/events/syscalls/sys_enter_read/format:
//
//   common_type/flags/preempt_count/pid    (8 bytes)
//   __syscall_nr int + padding              (8 bytes)
//   fd unsigned long                        (8 bytes)
//   buf char*                               (8 bytes)
//   count size_t                            (8 bytes)
struct sys_enter_rw_args {
    unsigned long long _pad;
    long id;
    unsigned long fd;
    unsigned long buf;
    unsigned long count;
};

struct sys_exit_args {
    unsigned long long _pad;
    long id;
    long ret;
};

// Op codes — devem bater com o lado Go (collector/io_ebpf.go).
#define OP_READ  0
#define OP_WRITE 1

struct io_inflight {
    __u64 ts_ns;
    __u32 fd;
    __u32 op;
    __u64 count_req;
};

// Evento publicado pro user-space via ring buffer. Layout fixo, lido com
// binary.LittleEndian no Go side. Mantenha em sincronia com IOEvent em
// internal/collector/io_ebpf.go.
struct io_event {
    __u64 ts_ns;
    __u64 lat_ns;
    __u64 bytes;       // ret value (se positivo)
    __u32 fd;
    __u32 op;
    __u32 tgid;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} io_target_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct io_inflight);
    __uint(max_entries, 10240);
} io_inflight_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB
} io_events SEC(".maps");

static __always_inline int is_io_target(void)
{
    __u32 key = 0;
    __u32 *target = bpf_map_lookup_elem(&io_target_pid, &key);
    if (!target || *target == 0)
        return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);
    return tgid == *target;
}

static __always_inline void enter_io(__u32 op, __u32 fd, __u64 count)
{
    if (!is_io_target())
        return;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct io_inflight inf = {
        .ts_ns     = bpf_ktime_get_ns(),
        .fd        = fd,
        .op        = op,
        .count_req = count,
    };
    bpf_map_update_elem(&io_inflight_map, &pid_tgid, &inf, BPF_ANY);
}

static __always_inline void exit_io(long ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct io_inflight *inf = bpf_map_lookup_elem(&io_inflight_map, &pid_tgid);
    if (!inf)
        return;

    struct io_event *e = bpf_ringbuf_reserve(&io_events, sizeof(*e), 0);
    if (e) {
        __u64 now = bpf_ktime_get_ns();
        e->ts_ns  = now;
        e->lat_ns = now - inf->ts_ns;
        e->bytes  = ret > 0 ? (__u64)ret : 0;
        e->fd     = inf->fd;
        e->op     = inf->op;
        e->tgid   = (__u32)(pid_tgid >> 32);
        e->_pad   = 0;
        bpf_ringbuf_submit(e, 0);
    }
    bpf_map_delete_elem(&io_inflight_map, &pid_tgid);
}

SEC("tracepoint/syscalls/sys_enter_read")
int handle_enter_read(struct sys_enter_rw_args *ctx)
{
    enter_io(OP_READ, (__u32)ctx->fd, ctx->count);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int handle_exit_read(struct sys_exit_args *ctx)
{
    if (!is_io_target())
        return 0;
    exit_io(ctx->ret);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int handle_enter_write(struct sys_enter_rw_args *ctx)
{
    enter_io(OP_WRITE, (__u32)ctx->fd, ctx->count);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int handle_exit_write(struct sys_exit_args *ctx)
{
    if (!is_io_target())
        return 0;
    exit_io(ctx->ret);
    return 0;
}
