//go:build linux && ebpf

package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trentas/ptop/pkg/collector"
)

// ─── budget: --overhead-budget detaches the heap probe, and says so (#154) ─
//
// A Set with only the heap probe and a 1% budget watches this process while one
// goroutine allocates as fast as it can. Each allocation costs a probe hit worth
// many times the allocation itself, so the estimate sits far above 1% of the
// process's CPU and the probe must go after three windows in a row:
//
//   - a ProbeChange says heap is now disabled, and why;
//   - the probe set a later handshake reads says the same;
//   - no heap snapshot is published after it, so no consumer reads the
//     silence as allocations stopping;
//   - ptop does not keep a CPU busy afterwards: a heap reader that took the
//     closed ring buffer for a transient error would spin forever.

func checkBudget(g *grader, pid int) {
	disable := make(map[string]bool)
	for _, name := range strings.Split(collector.KnownSubsystems(), ", ") {
		if name != collector.SubsystemHeap {
			disable[name] = true
		}
	}
	const budget = 1.0
	s := collector.NewSet(collector.SetConfig{PID: pid, Disable: disable, OverheadBudgetPct: budget})
	defer s.Stop()

	var (
		mu        sync.Mutex
		change    *collector.ProbeChange
		changeAt  time.Time
		lastHeap  time.Time
		overheads []float64
		after     []float64 // ptop's CPU in windows that start a second after the workload stopped
		stopped   time.Time
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus := collector.NewBus()
	h := bus.AddHandler(func(v any) {
		mu.Lock()
		defer mu.Unlock()
		switch x := v.(type) {
		case collector.ProbeChange:
			if change == nil {
				change, changeAt = &x, time.Now()
			}
		case collector.HeapStats:
			lastHeap = time.Now()
		case collector.CaptureCost:
			for _, p := range x.Probes {
				if p.Probe == collector.SubsystemHeap && p.OverheadKnown {
					overheads = append(overheads, p.OverheadPct)
				}
			}
			if !stopped.IsZero() && x.Timestamp.After(stopped.Add(1500*time.Millisecond)) && x.PtopKnown {
				after = append(after, x.PtopCPUPct)
			}
		}
	})
	defer bus.RemoveHandler(h)
	bus.Start(ctx, s.Collectors())

	var halt atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for !halt.Load() {
			plantedCostAlloc()
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := change != nil
		mu.Unlock()
		if got {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	halt.Store(true)
	<-done
	mu.Lock()
	stopped = time.Now()
	mu.Unlock()
	time.Sleep(3500 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	got := fmt.Sprintf("none; overheads seen %v", firstFloats(overheads, 6))
	if change != nil {
		got = fmt.Sprintf("a ProbeChange after the windows %v", firstFloats(overheads, 6))
	}
	if !g.check("budget", fmt.Sprintf("heap detached by a %.0f%% budget within 10s of allocating flat out", budget),
		change != nil, "a ProbeChange", got) {
		return
	}
	g.check("budget", "the change says heap is disabled, and why",
		change.Status.Name == collector.SubsystemHeap && change.Status.State == collector.ProbeDisabled &&
			strings.Contains(change.Status.Detail, "--overhead-budget"),
		"heap disabled (--overhead-budget …)", fmt.Sprintf("%s %s (%q)", change.Status.Name, change.Status.State, change.Status.Detail))
	var heap collector.ProbeStatus
	for _, st := range s.Probes() {
		if st.Name == collector.SubsystemHeap {
			heap = st
		}
	}
	g.check("budget", "the probe set a later handshake reads says disabled", heap.State == collector.ProbeDisabled,
		"disabled", string(heap.State))
	last := fmt.Sprintf("none (the last %v before it)", changeAt.Sub(lastHeap).Round(time.Millisecond))
	if lastHeap.After(changeAt) {
		last = fmt.Sprintf("one %v after it", lastHeap.Sub(changeAt).Round(time.Millisecond))
	}
	g.check("budget", "no heap snapshot after the detach", !lastHeap.After(changeAt.Add(100*time.Millisecond)), "none", last)
	maxAfter := 0.0
	for _, v := range after {
		maxAfter = max(maxAfter, v)
	}
	g.check("budget", "ptop idles once the workload stops (no reader spinning on the closed probe)",
		len(after) > 0 && maxAfter < 30, "< 30% of a core", fmt.Sprintf("%v", firstFloats(after, 4)))
}

func firstFloats(v []float64, n int) string {
	if len(v) > n {
		v = v[:n]
	}
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = fmt.Sprintf("%.0f%%", x)
	}
	return "[" + strings.Join(parts, " ") + "]"
}
