// SPDX-License-Identifier: GPL-2.0
//
// calib.bpf.c — what a uprobe costs the thread that trips it, on this host
// (#154).
//
// The heap probes hang off the allocator, so their cost is a per-hit cost
// times the target's allocation rate. Most of a hit is not the program: it is
// the trap into the kernel and back, which the kernel's own run-time
// accounting does not count and which differs by CPU and kernel. This program
// does nothing, so attached to a function in ptop's own process it measures
// exactly that: the entry trap of a uprobe. The heap programs time their own
// bodies (heap.bpf.c, goalloc.bpf.c), and the two together are the estimate.
//
// There is no uretprobe here, on purpose. A uretprobe rewrites the probed
// function's return address on the stack, and ptop is a Go program: a GC
// scanning that goroutine's stack meanwhile finds a return address in no Go
// function and the process dies (SIGSEGV in runtime.(*unwinder).next, seen in
// CI the first time a calibration ran beside a busy allocator). The entry trap
// leaves the stack alone, which is why the Go allocation lane hooks mallocgc
// with a uprobe and never a uretprobe.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("uprobe/calib_entry")
int calib_entry(void *ctx)
{
    return 0;
}
