// SPDX-License-Identifier: GPL-2.0
//
// calib.bpf.c — what a uprobe costs the thread that trips it, on this host
// (#154).
//
// The heap probes hang off the allocator, so their cost is a per-hit cost
// times the target's allocation rate. Most of a hit is not the program: it is
// the trap into the kernel and back, which the kernel's own run-time
// accounting does not count and which differs by CPU and kernel. These two
// programs do nothing, so attached to a function in ptop's own process they
// measure exactly that: the entry trap of a uprobe and the extra trap of a
// uretprobe. The heap programs time their own bodies (heap.bpf.c,
// goalloc.bpf.c), and the two together are the estimate.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("uprobe/calib_entry")
int calib_entry(void *ctx)
{
    return 0;
}

SEC("uretprobe/calib_return")
int calib_return(void *ctx)
{
    return 0;
}
