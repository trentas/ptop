/* SPDX-License-Identifier: GPL-2.0 */
/*
 * target.bpf.h — the target filter shared by every ptop eBPF program.
 *
 * Two ways to name what we are tracing:
 *
 * PID mode (PTOP_TARGET_PID). bpf_get_current_pid_tgid() returns PIDs in the
 * INITIAL pid namespace, while ptop's --pid is a namespace-local PID (what
 * /proc and ps show). Under a nested pid namespace (WSL2, Docker, LXC) the two
 * differ, so a plain `tgid == target` comparison never matched.
 *
 * bpf_get_ns_current_pid_tgid() (kernel 5.7+) is NOT a projection into any
 * namespace. It answers only when the current task's own pid namespace is the
 * one named by (dev, ino), with the task's pid there, and fails for every
 * other task. So the filter names the target's namespace (/proc/<pid>/ns/pid)
 * and compares with the target's pid inside it — the last entry of NSpid,
 * which the loader writes. That is the number /proc shows only when ptop
 * shares the namespace. Seen from an ancestor (the host, a `pid: host`
 * container), a containerized target is 1452007 in /proc and 1 in its own
 * namespace; comparing with 1452007 matched nothing, and every probe read
 * zero while reporting `active` (#197).
 *
 * CGROUP mode (PTOP_TARGET_CGROUP). A cgroup subtree is the target, and no PID
 * needs to be known in advance — which is what lets ptop attach to a container
 * or a whole pod (#94). The target cgroup sits in ptop_target_cgroup, and
 * bpf_current_task_under_cgroup() asks the kernel whether the current task is
 * inside its subtree, forks included.
 *
 * It used to be bpf_get_current_ancestor_cgroup_id(level) == id, with the
 * level computed by the loader as the depth below the cgroup2 mount. Inside a
 * cgroup namespace that mount's root is the namespace root, while the helper
 * counts from the host's root, so the level came out short and nothing ever
 * matched: every axis read zero, silently (#193). Nothing visible from inside
 * the namespace gives its root's depth. The kernel compares the cgroups
 * themselves here, so no depth has to cross the namespace boundary.
 */
#ifndef PTOP_TARGET_BPF_H
#define PTOP_TARGET_BPF_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define PTOP_TARGET_PID    0
#define PTOP_TARGET_CGROUP 1

/* Written by the Go loader (see internal/bpf/target.go). In PID mode dev+ino
 * identify the target's PID namespace and pid is its tgid within that
 * namespace (NSpid's last entry, not the number ptop's /proc shows — #197);
 * in CGROUP mode only mode is read, and the cgroup is in
 * ptop_target_cgroup. 24 bytes — keep targetFilter in target.go byte-for-byte
 * identical. */
struct target_filter {
    __u32 pid;
    __u32 mode;
    __u64 dev;
    __u64 ino;
};

/* CGROUP mode's target cgroup, in slot 0, written by the Go loader from an fd
 * of the cgroup's directory. Every program that includes this header has its
 * own; only a cgroup-mode loader fills it. A cgroup array takes no BTF key or
 * value type, hence the sizes. */
struct {
    __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} ptop_target_cgroup SEC(".maps");

/* cgroup_is_target returns 1 when the current task sits anywhere inside the
 * target cgroup's subtree. An empty slot is a negative error, never a match.
 * The Go side refuses the root of the hierarchy it sees, which on a host would
 * trace every process. */
static __always_inline int cgroup_is_target(void)
{
    return bpf_current_task_under_cgroup(&ptop_target_cgroup, 0) == 1;
}

/* pid_target_ns reports whether the current task is part of the target and
 * writes its pid/tgid into *out. target_map is an ARRAY[1] of
 * struct target_filter.
 *
 * The pids written in CGROUP mode are the ROOT-namespace ones: a cgroup
 * subtree can span pid namespaces, so there is no single namespace to project
 * into. Consumers reading tid/pid off cgroup-targeted events therefore see
 * host pids, not the container's view of them. */
static __always_inline int pid_target_ns(void *target_map,
                                          struct bpf_pidns_info *out)
{
    __u32 key = 0;
    struct target_filter *tf = bpf_map_lookup_elem(target_map, &key);
    if (!tf)
        return 0;

    if (tf->mode == PTOP_TARGET_CGROUP) {
        if (!cgroup_is_target())
            return 0;
        __u64 id = bpf_get_current_pid_tgid();
        out->pid = (__u32)id;
        out->tgid = (__u32)(id >> 32);
        return 1;
    }

    if (tf->pid == 0)
        return 0;
    if (bpf_get_ns_current_pid_tgid(tf->dev, tf->ino, out, sizeof(*out)) != 0)
        return 0;
    return out->tgid == tf->pid;
}

/* pid_is_target returns 1 when the current task belongs to the target,
 * whichever way the target was named. */
static __always_inline int pid_is_target(void *target_map)
{
    struct bpf_pidns_info ns = {};
    return pid_target_ns(target_map, &ns);
}

#endif /* PTOP_TARGET_BPF_H */
