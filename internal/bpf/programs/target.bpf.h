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
 * bpf_get_ns_current_pid_tgid() (kernel 5.7+) projects the current task's pid
 * into a specific namespace, identified by the (dev, ino) of
 * /proc/<pid>/ns/pid.
 *
 * CGROUP mode (PTOP_TARGET_CGROUP). A cgroup subtree is the target, and no PID
 * needs to be known in advance — which is what lets ptop attach to a container
 * or a whole pod (#94). bpf_get_current_ancestor_cgroup_id(level) returns the
 * id of the current task's ancestor cgroup at that depth, so every task inside
 * the target's subtree answers with the target's own id, forks included.
 */
#ifndef PTOP_TARGET_BPF_H
#define PTOP_TARGET_BPF_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define PTOP_TARGET_PID    0
#define PTOP_TARGET_CGROUP 1

/* Written by the Go loader (see internal/bpf/target.go). In PID mode dev+ino
 * identify the target's PID namespace and pid is its tgid within that
 * namespace; in CGROUP mode cgroup_id identifies the target cgroup and
 * cgroup_level is its depth below the cgroup root. 40 bytes — keep
 * targetFilter in target.go byte-for-byte identical. */
struct target_filter {
    __u32 pid;
    __u32 mode;
    __u64 dev;
    __u64 ino;
    __u64 cgroup_id;
    __u32 cgroup_level;
    __u32 _pad;
};

/* cgroup_is_target returns 1 when the current task sits anywhere inside the
 * target cgroup's subtree. Level 0 is the cgroup root, which would match every
 * process on the host — the Go side refuses to resolve to it, so a filter that
 * somehow carries it still needs cgroup_id to match. */
static __always_inline int cgroup_is_target(struct target_filter *tf)
{
    if (tf->cgroup_id == 0)
        return 0;
    return bpf_get_current_ancestor_cgroup_id(tf->cgroup_level) == tf->cgroup_id;
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
        if (!cgroup_is_target(tf))
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
