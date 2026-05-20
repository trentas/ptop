/* SPDX-License-Identifier: GPL-2.0 */
/*
 * target.bpf.h — namespace-aware target-process filter shared by every
 * ptop eBPF program.
 *
 * bpf_get_current_pid_tgid() returns PIDs in the INITIAL pid namespace.
 * ptop's --pid is a namespace-local PID (what /proc and ps show). Under a
 * nested pid namespace (WSL2, Docker, LXC) the two differ, so the old
 * `tgid == target` comparison never matched. bpf_get_ns_current_pid_tgid()
 * (kernel 5.7+) projects the current task's pid into a specific namespace,
 * identified by the (dev, ino) of /proc/<pid>/ns/pid.
 */
#ifndef PTOP_TARGET_BPF_H
#define PTOP_TARGET_BPF_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Written by the Go loader (see internal/bpf/target.go). dev+ino identify
 * the target's PID namespace; pid is the target tgid within that namespace. */
struct target_filter {
    __u32 pid;
    __u32 _pad;
    __u64 dev;
    __u64 ino;
};

/* pid_target_ns resolves the current task's pid/tgid inside the target's
 * namespace and writes them into *out. Returns 1 when the current task is
 * the target process, 0 otherwise. target_map is an ARRAY[1] of
 * struct target_filter. */
static __always_inline int pid_target_ns(void *target_map,
                                          struct bpf_pidns_info *out)
{
    __u32 key = 0;
    struct target_filter *tf = bpf_map_lookup_elem(target_map, &key);
    if (!tf || tf->pid == 0)
        return 0;
    if (bpf_get_ns_current_pid_tgid(tf->dev, tf->ino, out, sizeof(*out)) != 0)
        return 0;
    return out->tgid == tf->pid;
}

/* pid_is_target returns 1 when the current task belongs to the target
 * process. Use this anywhere the old is_*_target() helpers were used. */
static __always_inline int pid_is_target(void *target_map)
{
    struct bpf_pidns_info ns = {};
    return pid_target_ns(target_map, &ns);
}

#endif /* PTOP_TARGET_BPF_H */
