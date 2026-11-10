//go:build linux && ebpf

package main

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/unix"

	"github.com/trentas/ptop/internal/bpf"
	"github.com/trentas/ptop/pkg/collector"
)

// ─── cpukernel: the profile says how much of it is kernel time (#152) ──────
//
// The profile names user frames only, so time in a syscall is credited to the
// user frame that made it, and a consumer classifying sites by origin finds
// "zero kernel" by construction. The profile now says so (stack_scope USER)
// and counts the samples that caught the CPU in kernel mode. Two plants, each
// with an answer known in advance:
//
//   - a pure arithmetic burn, which never enters the kernel: its samples are
//     user-mode, all but a few ticks and faults;
//   - reads of 1 MiB from /dev/zero, where nearly all the time is the kernel
//     clearing the user buffer: its samples are kernel-mode, credited to the
//     syscall wrapper that entered the kernel.

const kernelPhase = 2500 * time.Millisecond

// plantedZeroRead reads /dev/zero until until: nearly all of it kernel time.
//
//go:noinline
func plantedZeroRead(fd int, buf []byte, until time.Time) {
	for time.Now().Before(until) {
		_, _ = unix.Read(fd, buf)
	}
}

// profileShares runs workload under a fresh CPU profile collector and sums
// its windows: all samples, the kernel-mode ones, the top site's, and the
// scope every window declared.
func profileShares(pid int, workload func()) (total, kernel uint64, top collector.CPUSite, scopes map[string]bool, err error) {
	c := collector.NewCPUProfEBPFCollector(bpf.CPUProfDefaultHz, nil)
	vals, err := collect(c, pid, 1200*time.Millisecond, workload)
	if err != nil {
		return 0, 0, top, nil, err
	}
	scopes = map[string]bool{}
	bySite := map[string]collector.CPUSite{}
	for _, v := range vals {
		p, ok := v.(collector.CPUProfile)
		if !ok {
			continue
		}
		scopes[p.StackScope] = true
		total += p.TotalSamples
		kernel += p.KernelSamples
		for _, s := range p.Sites {
			acc := bySite[s.Key()]
			if acc.Samples == 0 {
				acc = s
				acc.Samples, acc.KernelSamples = 0, 0
			}
			acc.Samples += s.Samples
			acc.KernelSamples += s.KernelSamples
			bySite[s.Key()] = acc
		}
	}
	for _, s := range bySite {
		if s.Samples > top.Samples {
			top = s
		}
	}
	return total, kernel, top, scopes, nil
}

func pct(a, b uint64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b) * 100
}

func checkCPUKernel(g *grader, pid int) {
	userTotal, userKernel, _, scopes, err := profileShares(pid, func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		cpuSplitSink += plantedSixty(time.Now().Add(kernelPhase))
	})
	if err != nil {
		g.broken("cpukernel", "profile a user-mode burn", err)
		return
	}
	g.check("cpukernel", "the profile declares its sites user frames only", len(scopes) == 1 && scopes[collector.StackScopeUser],
		collector.StackScopeUser, fmt.Sprint(scopes))
	g.check("cpukernel", "an arithmetic burn is user-mode time", userTotal >= 100 && pct(userKernel, userTotal) <= 10,
		"≥ 100 samples, ≤ 10% kernel-mode", fmt.Sprintf("%d of %d samples kernel-mode (%.1f%%)", userKernel, userTotal, pct(userKernel, userTotal)))

	zero, err := os.Open("/dev/zero")
	if err != nil {
		g.broken("cpukernel", "open /dev/zero", err)
		return
	}
	defer zero.Close()
	buf := make([]byte, 1<<20)
	kTotal, kKernel, top, _, err := profileShares(pid, func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		plantedZeroRead(int(zero.Fd()), buf, time.Now().Add(kernelPhase))
	})
	if err != nil {
		g.broken("cpukernel", "profile /dev/zero reads", err)
		return
	}
	g.check("cpukernel", "1 MiB reads of /dev/zero are kernel-mode time (#152)", kTotal >= 100 && pct(kKernel, kTotal) >= 60,
		"≥ 100 samples, ≥ 60% kernel-mode", fmt.Sprintf("%d of %d samples kernel-mode (%.1f%%)", kKernel, kTotal, pct(kKernel, kTotal)))
	name := top.Func
	if name == "" {
		name = top.Module
	}
	g.check("cpukernel", fmt.Sprintf("the top site (%s) says its share is kernel time", name),
		top.Samples > 0 && pct(top.KernelSamples, top.Samples) >= 80,
		"≥ 80% of its samples kernel-mode", fmt.Sprintf("%d of %d", top.KernelSamples, top.Samples))
}
