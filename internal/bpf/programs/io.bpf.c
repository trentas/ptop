// SPDX-License-Identifier: GPL-2.0
//
// io.bpf.c — traces synchronous I/O syscalls (read/write) of the target PID,
// measures per-call latency, AND captures filesystem *semantics* (#57):
// permission denials (open/openat → EACCES/EPERM), deletes (unlink/unlinkat),
// and renames (rename/renameat2) with their real paths. Both rides the same
// process-context target filter (is_io_target) but uses separate maps + a
// separate ring buffer so the fs-event path is independent of the throughput
// path.
//
// Maps:
//   io_target_pid       ARRAY[1]   struct target_filter (written by the Go loader)
//   io_inflight_map     HASH       tgid_pid → {ts_ns, fd, op, count_req, ino}
//                                  tracks an in-flight read/write to correlate
//                                  enter/exit
//   io_restarting       LRU_HASH   tgid_pid → a read/write stopped by a signal
//                                  that the kernel may re-run (restart.bpf.h,
//                                  #160)
//   io_stats            HASH       {tgid, fd, ino} → reads, writes, bytes,
//                                  latency sum (#181)
//   io_totals           PERCPU_ARRAY[1]  the latency histogram, and the calls
//                                  io_stats had no room for (#181)
//   io_events           RINGBUF    naming channel: every successful open with
//                                  its path (#162), a key's first call, and a
//                                  key's final counts when the target closes it
//   fs_inflight_map     HASH       tgid_pid → {op, path ptr, newpath ptr} (#57)
//   fs_events           RINGBUF    fs-semantics channel — op, ret, path(s) (#57)
//
// Why syscall-level (not block-level)?
//   block:block_rq_* gives REAL disk latency (excludes cache). But resolving
//   the file path requires vmlinux.h or CO-RE. Here we use sys_enter_/sys_exit_
//   tracepoints that give the fd directly — Go resolves fd→path via
//   /proc/<pid>/fd. Trade-off: we show syscall-level I/O (includes cache hits),
//   which is what the user sees in "files accessed" and matches the F5 mockup.
//
// Why raw_syscalls/sys_{enter,exit} and not syscalls/sys_enter_<name> (#159):
//   on kernel 7.0 the per-syscall events for write, openat, unlinkat and
//   renameat* copy the user buffer or path into the event, and on that path the
//   BPF program never ran for calls made on any CPU but the first: measured,
//   20 of 20 writes and unlinks seen on CPU 0, 0 of 20 on CPU 1, every run.
//   read, whose event copies nothing, was seen on both. raw_syscalls carries
//   only the number and the six raw arguments, so nothing on its path reads
//   user memory, and the syscalls axis has counted exactly on every CPU through
//   it. The cost is that it fires for EVERY syscall on the host, so the number
//   is tested first and the target filter only after it.
//
//   The numbers come from the kernel's own <asm/unistd.h>, for the architecture
//   the object is compiled on (see "Build tags" in CLAUDE.md, #123). They are
//   the 64-bit native table: a 32-bit (compat) task numbers its syscalls from
//   another one, so the loader refuses a 32-bit target in pid mode (io.go).
//
// Which file a read or write hit (#162):
//   the collector used to name the file by reading /proc/<pid>/fd/<n> when it
//   PROCESSED the event, and remembered the answer by fd number. A file closed
//   by then lost its name, and a reused number was credited to the file that
//   held it before. So the probe now says which file it was when the call ran:
//   each read and write is keyed by the inode number of the file behind its fd,
//   read at sys_enter (fdfile.bpf.h), and every successful open puts a record
//   on io_events with the new fd, its inode and the path the program passed.
//
// Why the counts stay in the kernel (#181):
//   one ring record per read and write cost a syscall-bound target 4-5x its
//   throughput: ~600ns in sys_exit, nearly all of it the record and the wakeup
//   of the reader, for events the collector only ever summed. So sys_exit adds
//   the call to its file's entry in io_stats and to the histogram in io_totals,
//   and the collector reads both every window. The totals stay exact.
//
//   io_events still carries what has to be read while the file is open, and
//   what would otherwise be lost:
//     - an open, so a file is named by the path it was opened by (#162);
//     - a key's first call (REC_SEEN), so one the probe saw no open for (a
//       socket, a pipe, a file opened before the capture) is named from its
//       fd's link before it can be closed;
//     - a close of an fd that has a key (REC_CLOSE): its final counts, and then
//       the key is deleted. That keeps io_stats as big as the set of files open
//       with I/O, not every file the target ever touched.
//   One ring, consumed in reservation order: an open's record comes before its
//   key's first call, and that before its close. A key's `gen` is when it was
//   created, so the collector tells one life of a (fd, inode) from the next.
//
//   A key whose fd is closed some other way (dup2 over it, close_range, the
//   process exiting) stays until the collector retires it: it deletes keys
//   idle for 30s, folding in what they held.
//
//   A call io_stats has no room for still counts in the histogram, and in
//   io_totals' lost_* fields, which the collector publishes as a row of its
//   own. It is never dropped silently.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <asm/unistd.h>
#include "target.bpf.h"
#include "restart.bpf.h"
#include "fdfile.bpf.h"

char LICENSE[] SEC("license") = "GPL";

// raw_syscalls/sys_exit layout: common header (8B), the syscall number, the
// return value. sys_enter's is struct sys_enter_args, below.
struct sys_exit_args {
    unsigned long long _pad;
    long id;
    long ret;
};

// Op codes — must match IOOp* in internal/bpf/io.go.
#define OP_READ  0
#define OP_WRITE 1

// Record kinds on io_events — must match IORec* in internal/bpf/io.go.
#define REC_OPEN  0 // a successful open: the path that names the fd it returned
#define REC_SEEN  1 // a key's first read or write
#define REC_CLOSE 2 // the target closed an fd that had a key: its final counts

#define FS_PATH_MAX 256

// The histogram's buckets, by latency: <0.1ms, <1ms, <5ms, <20ms, the rest.
// They are the labels the TUI and the wire carry (LatencyBucket).
#define IO_BUCKETS 5

// io_stats' size. A key lives while its fd is open with I/O on it, so this is
// the number of such files the target can hold before calls go to lost_*.
#define IO_STATS_MAX 16384

struct io_inflight {
    __u64 ts_ns;
    __u32 fd;
    __u32 op;
    __u64 count_req;
    __u64 end_ns; // in io_restarting: when the signal stopped it
    __u64 ino;    // the file behind fd when the call entered (#162)
};

// The file a call hit: the process, the fd, and the inode behind it then.
// Keep in sync with IOKey in internal/bpf/io.go.
struct io_key {
    __u32 tgid;
    __u32 fd;
    __u64 ino; // 0 = the fd table could not be read
};

// One key's counts since it was created. Keep in sync with IOStat.
struct io_stat {
    __u64 gen;    // bpf_ktime_get_ns() when the entry was created
    __u64 reads;
    __u64 writes;
    __u64 bytes;  // returned by the calls that succeeded
    __u64 lat_ns; // summed over reads and writes
};

// Per CPU, cumulative since the program loaded. Keep in sync with IOTotals.
struct io_totals {
    __u64 hist[2 * IO_BUCKETS]; // [op * IO_BUCKETS + bucket]
    // Calls io_stats had no room for: in the histogram, in no file's row.
    __u64 lost_reads;
    __u64 lost_writes;
    __u64 lost_bytes;
    __u64 lost_lat_ns;
};

// The header of every io_events record, 32 bytes. Keep in sync with
// decodeIORecord in internal/bpf/io.go.
struct io_record {
    __u32 kind; // REC_*
    __u32 tgid;
    __u32 fd;
    __s32 dfd;  // REC_OPEN: the directory fd the path is relative to
    __u64 ino;
    __u64 gen;  // REC_SEEN, REC_CLOSE: the key's gen
};

// REC_OPEN: fd is the descriptor the open returned, path as the program
// passed it — possibly relative to dfd.
struct io_open_record {
    struct io_record h;
    char path[FS_PATH_MAX];
};

// REC_CLOSE: the key's counts when the target closed its fd.
struct io_close_record {
    struct io_record h;
    struct io_stat s;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct target_filter);
    __uint(max_entries, 1);
} io_target_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct io_inflight);
    __uint(max_entries, 10240);
} io_inflight_map SEC(".maps");

// LRU: a thread killed inside the call never settles it.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);
    __type(value, struct io_inflight);
    __uint(max_entries, 10240);
} io_restarting SEC(".maps");

// Not LRU: an eviction would lose a key's counts without a trace. Full, it
// refuses the new key and the call goes to lost_*, which is published.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct io_key);
    __type(value, struct io_stat);
    __uint(max_entries, IO_STATS_MAX);
} io_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct io_totals);
    __uint(max_entries, 1);
} io_totals SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB
} io_events SEC(".maps");

static __always_inline int is_io_target(void)
{
    return pid_is_target(&io_target_pid);
}

static __always_inline __u32 lat_bucket(__u64 ns)
{
    if (ns < 100000ULL)
        return 0;
    if (ns < 1000000ULL)
        return 1;
    if (ns < 5000000ULL)
        return 2;
    if (ns < 20000000ULL)
        return 3;
    return 4;
}

// emit_seen tells the collector a key exists, while its fd is most likely
// still open: a file the probe saw no open for is named from the fd's link.
static __always_inline void emit_seen(const struct io_key *k, __u64 gen)
{
    struct io_record *r = bpf_ringbuf_reserve(&io_events, sizeof(*r), 0);
    if (!r)
        return; // the collector names it when it reads the map instead
    r->kind = REC_SEEN;
    r->tgid = k->tgid;
    r->fd   = k->fd;
    r->dfd  = 0;
    r->ino  = k->ino;
    r->gen  = gen;
    bpf_ringbuf_submit(r, 0);
}

// account_io adds one finished read or write to its file's key and to the
// histogram (#181). It replaces a ring record per call.
static __always_inline void account_io(const struct io_inflight *inf, __u64 end, long ret, __u32 tgid)
{
    __u32 op = inf->op == OP_WRITE ? OP_WRITE : OP_READ;
    __u64 lat = end - inf->ts_ns;
    __u64 bytes = ret > 0 ? (__u64)ret : 0;

    __u32 zero = 0;
    struct io_totals *t = bpf_map_lookup_elem(&io_totals, &zero);
    if (t) {
        __u32 i = op * IO_BUCKETS + lat_bucket(lat);
        if (i < 2 * IO_BUCKETS)
            t->hist[i]++;
    }

    struct io_key key = { .tgid = tgid, .fd = inf->fd, .ino = inf->ino };
    struct io_stat *s = bpf_map_lookup_elem(&io_stats, &key);
    if (!s) {
        struct io_stat init = {
            .gen    = end,
            .reads  = op == OP_READ,
            .writes = op == OP_WRITE,
            .bytes  = bytes,
            .lat_ns = lat,
        };
        if (bpf_map_update_elem(&io_stats, &key, &init, BPF_NOEXIST) == 0) {
            emit_seen(&key, end);
            return;
        }
        // Another CPU created it first, or the map is full.
        s = bpf_map_lookup_elem(&io_stats, &key);
        if (!s) {
            if (t) {
                if (op == OP_READ)
                    t->lost_reads++;
                else
                    t->lost_writes++;
                t->lost_bytes  += bytes;
                t->lost_lat_ns += lat;
            }
            return;
        }
    }
    if (op == OP_READ)
        __sync_fetch_and_add(&s->reads, 1);
    else
        __sync_fetch_and_add(&s->writes, 1);
    __sync_fetch_and_add(&s->bytes, bytes);
    __sync_fetch_and_add(&s->lat_ns, lat);
}

// close_io hands the collector a key's final counts when the target closes
// its fd, and deletes the key. Run at sys_enter, while fd still holds the file.
static __always_inline void close_io(__u32 fd)
{
    if (!is_io_target())
        return;
    struct io_key key = {
        .tgid = (__u32)(bpf_get_current_pid_tgid() >> 32),
        .fd   = fd,
        .ino  = fd_ino(fd),
    };
    struct io_stat *s = bpf_map_lookup_elem(&io_stats, &key);
    if (!s)
        return;
    struct io_close_record *r = bpf_ringbuf_reserve(&io_events, sizeof(*r), 0);
    if (!r)
        return; // left in place: the collector reads it there and retires it
    r->h.kind = REC_CLOSE;
    r->h.tgid = key.tgid;
    r->h.fd   = fd;
    r->h.dfd  = 0;
    r->h.ino  = key.ino;
    r->h.gen  = s->gen;
    r->s      = *s;
    bpf_ringbuf_submit(r, 0);
    bpf_map_delete_elem(&io_stats, &key);
}

// emit_open names the file a successful open installed at fd, on the same ring
// as the first call on it (#162).
static __always_inline void emit_open(__u32 fd, __s32 dfd, __u64 path, __u32 tgid)
{
    struct io_open_record *o = bpf_ringbuf_reserve(&io_events, sizeof(*o), 0);
    if (!o)
        return;
    o->h.kind  = REC_OPEN;
    o->h.tgid  = tgid;
    o->h.fd    = fd;
    o->h.dfd   = dfd;
    o->h.ino   = fd_ino(fd);
    o->h.gen   = 0;
    o->path[0] = '\0';
    if (path)
        bpf_probe_read_user_str(o->path, sizeof(o->path), (const void *)path);
    bpf_ringbuf_submit(o, 0);
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
        .ino       = fd_ino(fd),
    };
    // The kernel re-running a read or write a signal stopped: one call, timed
    // from its first entry (#160).
    struct io_inflight *r = bpf_map_lookup_elem(&io_restarting, &pid_tgid);
    if (r && r->op == op && r->fd == fd && r->count_req == count) {
        inf.ts_ns = r->ts_ns;
        bpf_map_delete_elem(&io_restarting, &pid_tgid);
    }
    bpf_map_update_elem(&io_inflight_map, &pid_tgid, &inf, BPF_ANY);
}

static __always_inline void exit_io(long ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct io_inflight *inf = bpf_map_lookup_elem(&io_inflight_map, &pid_tgid);
    if (!inf)
        return;

    __u64 now = bpf_ktime_get_ns();
    if (ret_restarts(ret)) {
        // Not over yet, or over with EINTR: restart.bpf.h.
        struct io_inflight r = *inf;
        r.end_ns = now;
        bpf_map_update_elem(&io_restarting, &pid_tgid, &r, BPF_ANY);
    } else {
        account_io(inf, now, ret, (__u32)(pid_tgid >> 32));
    }
    bpf_map_delete_elem(&io_inflight_map, &pid_tgid);
}

// sigreturn_io settles a stopped read or write when the handler that stopped
// it returns EINTR to it: the call ended at the exit already seen.
static __always_inline void sigreturn_io(long ret)
{
    if (ret != -PTOP_EINTR)
        return;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct io_inflight *r = bpf_map_lookup_elem(&io_restarting, &pid_tgid);
    if (!r)
        return;
    account_io(r, r->end_ns, -PTOP_EINTR, (__u32)(pid_tgid >> 32));
    bpf_map_delete_elem(&io_restarting, &pid_tgid);
}

// ─── #57 filesystem semantics: permission denials, deletes, renames ───────────
//
// These syscalls run in process context, so they reuse is_io_target(). We stash
// the user-space path pointer(s) at sys_enter and read the string at sys_exit
// (where the return value — hence EACCES/EPERM — is known). The user path buffer
// is still mapped at exit (same task), so reading the pointer there is valid —
// the proven libbpf-tools opensnoop approach, which avoids carrying a large
// string through the inflight map.
//
// An open that SUCCEEDS is not an fs event: it goes to io_events as the record
// that names the new fd (emit_open, #162).

#define FS_OP_OPEN_DENIED 0 // open/openat returned EACCES/EPERM
#define FS_OP_UNLINK      1 // unlink/unlinkat
#define FS_OP_RENAME      2 // rename/renameat/renameat2

#define EACCES 13
#define EPERM  1

#define PTOP_AT_FDCWD -100

// raw_syscalls/sys_enter layout: common header (8B), the syscall number, and
// its six arguments as unsigned long — whatever the syscall, which is why one
// program can serve read, write and the fs-semantics calls alike.
struct sys_enter_args {
    unsigned long long _pad;
    long id;
    unsigned long args[6];
};

// fs_inflight stashes the user path pointer(s) between sys_enter and sys_exit.
// Keyed by pid_tgid — a thread is in exactly one syscall at a time, so no
// overwrite races. Tiny value (pointers only); the string is read at exit.
struct fs_inflight {
    __u32 op;
    __s32 dfd;     // OPEN: the directory fd path is relative to
    __u64 path;    // const char __user *
    __u64 newpath; // const char __user * (RENAME); 0 otherwise
};

// fs_event is published to user-space via the fs_events ring buffer. Fixed
// layout (536 bytes), read with binary.LittleEndian on the Go side — keep in
// sync with FSEventRecord in internal/bpf/io.go.
struct fs_event {
    __u64 ts_ns;
    __u32 tgid;
    __s32 ret; // syscall return: negative errno on failure, >=0 on success
    __u32 op;  // FS_OP_*
    __u32 _pad;
    char  path[FS_PATH_MAX];
    char  newpath[FS_PATH_MAX]; // RENAME destination; "" otherwise
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct fs_inflight);
    __uint(max_entries, 10240);
} fs_inflight_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 19); // 512KB — fs events are low-rate
} fs_events SEC(".maps");

static __always_inline void fs_enter(__u32 op, __s32 dfd, __u64 path, __u64 newpath)
{
    if (!is_io_target())
        return;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct fs_inflight inf = {
        .op      = op,
        .dfd     = dfd,
        .path    = path,
        .newpath = newpath,
    };
    bpf_map_update_elem(&fs_inflight_map, &pid_tgid, &inf, BPF_ANY);
}

// fs_exit publishes the event when warranted. For OPEN we only surface denials
// (EACCES/EPERM); unlink/rename always publish — a failed delete/rename is still
// notable — carrying the errno in ret. The inflight lookup is itself the target
// filter (only target threads ever stash an entry), so no is_io_target() here.
static __always_inline void fs_exit(long ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct fs_inflight *inf = bpf_map_lookup_elem(&fs_inflight_map, &pid_tgid);
    if (!inf)
        return;
    __u32 op = inf->op;
    __s32 dfd = inf->dfd;
    __u64 path = inf->path;
    __u64 newpath = inf->newpath;
    bpf_map_delete_elem(&fs_inflight_map, &pid_tgid);

    if (op == FS_OP_OPEN_DENIED) {
        if (ret >= 0) {
            emit_open((__u32)ret, dfd, path, (__u32)(pid_tgid >> 32));
            return;
        }
        if (ret != -EACCES && ret != -EPERM)
            return;
    }

    struct fs_event *e = bpf_ringbuf_reserve(&fs_events, sizeof(*e), 0);
    if (!e)
        return;
    e->ts_ns      = bpf_ktime_get_ns();
    e->tgid       = (__u32)(pid_tgid >> 32);
    e->ret        = (__s32)ret;
    e->op         = op;
    e->_pad       = 0;
    e->path[0]    = '\0';
    e->newpath[0] = '\0';
    if (path)
        bpf_probe_read_user_str(e->path, sizeof(e->path), (const void *)path);
    if (newpath)
        bpf_probe_read_user_str(e->newpath, sizeof(e->newpath), (const void *)newpath);
    bpf_ringbuf_submit(e, 0);
}

// ─── dispatch ────────────────────────────────────────────────────────────────
//
// One pair for every syscall on the host (#159). The number is tested before
// anything else: almost no syscall is one of these, and almost none is the
// target's. The per-op argument positions:
//   read/write(fd, buf, count)                          fd args[0], count args[2]
//   close(fd)                                           fd args[0]
//   open(path, …)                  unlink(path)         path args[0]
//   openat(dfd, path, …)           unlinkat(dfd, path, flag)   path args[1]
//   openat2(dfd, path, how, size)                       path args[1]
//   rename(old, new)                                    args[0], args[1]
//   renameat/renameat2(olddfd, old, newdfd, new, …)     args[1], args[3]
// Modern libcs route open/unlink/rename to the *at forms, and arm64 has none of
// the legacy three; they are matched where the architecture defines them.

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct sys_enter_args *ctx)
{
    switch (ctx->id) {
    case __NR_read:
        enter_io(OP_READ, (__u32)ctx->args[0], ctx->args[2]);
        break;
    case __NR_write:
        enter_io(OP_WRITE, (__u32)ctx->args[0], ctx->args[2]);
        break;
    case __NR_close:
        close_io((__u32)ctx->args[0]);
        break;
    case __NR_openat:
        fs_enter(FS_OP_OPEN_DENIED, (__s32)ctx->args[0], ctx->args[1], 0);
        break;
#ifdef __NR_openat2
    case __NR_openat2:
        fs_enter(FS_OP_OPEN_DENIED, (__s32)ctx->args[0], ctx->args[1], 0);
        break;
#endif
    case __NR_unlinkat:
        fs_enter(FS_OP_UNLINK, 0, ctx->args[1], 0);
        break;
    case __NR_renameat2:
        fs_enter(FS_OP_RENAME, 0, ctx->args[1], ctx->args[3]);
        break;
#ifdef __NR_renameat
    case __NR_renameat:
        fs_enter(FS_OP_RENAME, 0, ctx->args[1], ctx->args[3]);
        break;
#endif
#ifdef __NR_open
    case __NR_open:
        fs_enter(FS_OP_OPEN_DENIED, PTOP_AT_FDCWD, ctx->args[0], 0);
        break;
#endif
#ifdef __NR_unlink
    case __NR_unlink:
        fs_enter(FS_OP_UNLINK, 0, ctx->args[0], 0);
        break;
#endif
#ifdef __NR_rename
    case __NR_rename:
        fs_enter(FS_OP_RENAME, 0, ctx->args[0], ctx->args[1]);
        break;
#endif
    }
    return 0;
}

// The exits need no target filter of their own: only a target thread's enter
// stashed an in-flight entry, and the lookup is keyed by the thread.
SEC("tracepoint/raw_syscalls/sys_exit")
int handle_sys_exit(struct sys_exit_args *ctx)
{
    switch (ctx->id) {
    case __NR_read:
    case __NR_write:
        exit_io(ctx->ret);
        break;
    // rt_sigreturn's exit carries the id the restored frame holds, -1 on x86
    // and arm64 (restore_sigcontext forgets the syscall). Its return is the
    // restored register: -EINTR when the stopped call returns EINTR (#160).
    case -1:
    case __NR_rt_sigreturn:
        sigreturn_io(ctx->ret);
        break;
    case __NR_openat:
#ifdef __NR_openat2
    case __NR_openat2:
#endif
    case __NR_unlinkat:
    case __NR_renameat2:
#ifdef __NR_renameat
    case __NR_renameat:
#endif
#ifdef __NR_open
    case __NR_open:
#endif
#ifdef __NR_unlink
    case __NR_unlink:
#endif
#ifdef __NR_rename
    case __NR_rename:
#endif
        fs_exit(ctx->ret);
        break;
    }
    return 0;
}
