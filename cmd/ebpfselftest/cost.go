//go:build linux && ebpf

package main

import (
	"fmt"
	"runtime"
	"slices"
	"time"

	"golang.org/x/sys/unix"

	"github.com/trentas/ptop/internal/bpf"
	"github.com/trentas/ptop/pkg/collector"
)

// ─── cost: the estimate against the cost it estimates (#154) ───────────────
//
// The capture says what the heap probe costs the target. The planted answer is
// the cost itself: one thread allocates, and its CPU time per allocation is
// measured with the probe detached and then attached. The difference is what
// a probe hit costs that thread, by its own clock; the estimate must land near
// it.

var costSink []byte

//go:noinline
func plantedCostAlloc() { costSink = make([]byte, 64) }

const costAllocs = 500_000

// allocNs is the smallest per-allocation CPU time of a few rounds on a locked
// thread: noise only ever adds time.
func allocNs() float64 {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var rounds []float64
	for r := 0; r < 3; r++ {
		var a, b unix.Timespec
		_ = unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &a)
		for i := 0; i < costAllocs; i++ {
			plantedCostAlloc()
		}
		_ = unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &b)
		rounds = append(rounds, float64(b.Nano()-a.Nano())/costAllocs)
	}
	return slices.Min(rounds)
}

func checkCost(g *grader, pid int) {
	bare := allocNs()

	heap := collector.NewHeapEBPFCollector(bpf.GoAllocDefaultSampleBytes, nil)
	if err := heap.Start(pid); err != nil {
		g.broken("cost", "attach the heap probe", err)
		return
	}
	defer heap.Stop()
	cost := collector.NewCostCollector(map[string]collector.CostSource{"heap": heap})
	var probed float64
	vals, err := collect(cost, pid, 1200*time.Millisecond, func() {
		time.Sleep(1200 * time.Millisecond) // the calibration, and a first window
		probed = allocNs()
	})
	if err != nil {
		g.broken("cost", "start the cost collector", err)
		return
	}

	// The estimate per hit, weighted by each window's hits: the Go lane has no
	// uretprobe, so a hit is an entry.
	var entries uint64
	var weighted float64
	var last collector.ProbeCost
	for _, v := range vals {
		cc, ok := v.(collector.CaptureCost)
		if !ok {
			continue
		}
		for _, p := range cc.Probes {
			if p.Probe == "heap" && p.Entries > 0 {
				entries += p.Entries
				weighted += float64(p.Entries) * (p.ProgramNs + p.TrapEntryNs)
				last = p
			}
		}
	}
	if entries == 0 {
		g.broken("cost", "a heap cost estimate", fmt.Errorf("no window with heap hits in %d samples", len(vals)))
		return
	}
	g.note("cost", "calibration: %s; trap %.0fns entry, %.0fns return", last.Calibration, last.TrapEntryNs, last.TrapReturnNs)
	g.check("cost", "the entry trap was calibrated on this host", last.TrapEntryNs > 0, "> 0", fmt.Sprintf("%.0fns", last.TrapEntryNs))
	g.check("cost", "every allocation is a counted hit", entries >= 3*costAllocs,
		fmt.Sprintf("≥ %d (3 rounds × %d)", 3*costAllocs, costAllocs), fmt.Sprint(entries))

	measured := probed - bare
	estimate := weighted / float64(entries)
	ratio := estimate / measured
	g.check("cost", fmt.Sprintf("estimated cost of a hit against the measured (%.0fns bare, %.0fns probed)", bare, probed),
		measured > 0 && ratio >= 0.5 && ratio <= 2,
		fmt.Sprintf("within 2× of %.0fns", measured), fmt.Sprintf("%.0fns (%.2f×)", estimate, ratio))
}
