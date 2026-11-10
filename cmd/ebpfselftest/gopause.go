//go:build linux && ebpf

package main

import (
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/trentas/ptop/internal/bpf"
	"github.com/trentas/ptop/pkg/collector"
)

// checkGoPauses grades the stop-the-world axis (#175) against pauses this
// process plants on itself. With the automatic GC off, the only stops in the
// window are the forced collections, and every runtime.GC() stops the world
// exactly twice: sweep termination, then mark termination.
//
// Then a target that is not a Go program: the probe must say unsupported, not
// attach and report no pause.
func checkGoPauses(g *grader, pid int) {
	const cycles = 20
	old := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(old)

	var first, last collector.GoPauses
	seen := 0
	c := collector.NewGoPauseEBPFCollector()
	vals, err := collect(c, pid, 1500*time.Millisecond, func() {
		// One sample before the planted pauses, so the window's difference
		// starts from a reading the stops are not in.
		time.Sleep(1300 * time.Millisecond)
		for i := 0; i < cycles; i++ {
			runtime.GC()
		}
	})
	if err != nil {
		g.broken("gopause", "attach to this process's runtime", err)
		return
	}
	for _, v := range vals {
		if p, ok := v.(collector.GoPauses); ok {
			if seen == 0 {
				first = p
			}
			last = p
			seen++
		}
	}
	if !g.check("gopause", "samples published", seen >= 2, ">= 2", fmt.Sprint(seen)) {
		return
	}
	n := last.Count - first.Count
	g.check("gopause", fmt.Sprintf("stop-the-worlds for %d forced GC cycles, automatic GC off", cycles),
		n >= 2*cycles && n <= 2*cycles+2,
		fmt.Sprintf("%d (two a cycle), at most 2 more", 2*cycles), fmt.Sprint(n))
	if n == 0 {
		return
	}
	mean := time.Duration((last.SumNs - first.SumNs) / n)
	g.check("gopause", "mean pause", mean > time.Microsecond && mean < 10*time.Millisecond,
		"(1µs, 10ms)", mean.String())
	var bucketed, long uint64
	for i := range last.Buckets {
		d := last.Buckets[i] - first.Buckets[i]
		bucketed += d
		if i >= 17 { // [2^17 µs, …): over 131 ms
			long += d
		}
	}
	g.check("gopause", "every pause in exactly one bucket", bucketed == n, fmt.Sprint(n), fmt.Sprint(bucketed))
	g.check("gopause", "no pause over 131ms in an idle process", long == 0, "0", fmt.Sprint(long))

	// pid 1 is init, not a Go program here: unsupported, never an empty axis.
	if _, err := bpf.OpenGoPauseTracer(1); !errors.Is(err, bpf.ErrNotGo) {
		got := "attached"
		if err != nil {
			got = err.Error()
		}
		g.check("gopause", "a target that is not a Go program is unsupported", false, "ErrNotGo", got)
	} else {
		g.check("gopause", "a target that is not a Go program is unsupported", true, "ErrNotGo", "ErrNotGo")
	}
}
