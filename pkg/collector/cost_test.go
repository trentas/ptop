package collector

import (
	"math"
	"testing"
	"time"

	"github.com/trentas/ptop/internal/bpf"
)

type fakeCostSource struct{ c bpf.ProbeCostCounters }

func (f *fakeCostSource) ProbeCost() (bpf.ProbeCostCounters, error) { return f.c, nil }

// The estimate is the measured program time per hit on every hit, plus the
// calibrated trap on each entry and each return.
func TestCostEstimate(t *testing.T) {
	src := &fakeCostSource{}
	c := NewCostCollector(map[string]CostSource{"heap": src})
	c.trap = bpf.UprobeTrapCost{EntryNs: 500, ReturnNs: 150}
	c.calibration = "test"

	t0 := time.Unix(100, 0)
	first, _ := c.sample(t0)
	if first.PtopKnown || len(first.Probes) != 0 {
		t.Fatalf("the first sample has no window: %+v", first)
	}

	// One second: 1M entries and 1M returns, 31,250 of the 2M hits timed at
	// 100ns each.
	src.c = bpf.ProbeCostCounters{Entries: 1_000_000, Returns: 1_000_000, Timed: 31_250, TimedNs: 3_125_000}
	got, _ := c.sample(t0.Add(time.Second))
	if !got.PtopKnown || len(got.Probes) != 1 {
		t.Fatalf("second sample = %+v", got)
	}
	p := got.Probes[0]
	// 2M × 100ns + 1M × 500ns + 1M × 150ns = 850ms of a 1s window.
	if p.Probe != "heap" || p.Entries != 1_000_000 || p.Returns != 1_000_000 || p.ProgramNs != 100 ||
		math.Abs(p.EstimatePct-85) > 1e-9 || p.Calibration != "test" {
		t.Errorf("estimate = %+v, want 85%% of a core", p)
	}

	// A window that timed no hit keeps the last known program time.
	src.c = bpf.ProbeCostCounters{Entries: 1_000_100, Returns: 1_000_000, Timed: 31_250, TimedNs: 3_125_000}
	cc, _ := c.sample(t0.Add(2 * time.Second))
	p = cc.Probes[0]
	if p.Entries != 100 || p.ProgramNs != 100 || math.Abs(p.EstimatePct-0.006) > 1e-9 {
		t.Errorf("quiet window = %+v, want 100 entries at 600ns", p)
	}
}

// With no probe to measure, the capture still says what ptop itself costs.
func TestCostWithoutProbes(t *testing.T) {
	c := NewCostCollector(nil)
	c.sample(time.Unix(100, 0))
	got, _ := c.sample(time.Unix(101, 0))
	if !got.PtopKnown || got.PtopCPUPct < 0 || len(got.Probes) != 0 {
		t.Errorf("no-probe sample = %+v", got)
	}
}

// --overhead-budget: three windows in a row above the budget detach the probe,
// once, and say so; a window back under it resets the count.
func TestOverheadBudgetDetachesAfterThreeWindows(t *testing.T) {
	src := &fakeCostSource{}
	var target time.Duration
	var detached []string
	c := NewCostCollector(map[string]CostSource{"heap": src}).WithBudget(10, func(name, reason string) error {
		detached = append(detached, name+": "+reason)
		return nil
	})
	c.trap = bpf.UprobeTrapCost{EntryNs: 500}
	c.targetCPU = func() (time.Duration, bool) { return target, true }

	t0 := time.Unix(100, 0)
	c.sample(t0)
	// step advances one second in which the target used targetMs of CPU and
	// made hits entries, each estimated at 500ns of trap.
	step := func(i int, hits uint64, targetMs int) (CaptureCost, []ProbeChange) {
		src.c.Entries += hits
		target += time.Duration(targetMs) * time.Millisecond
		return c.sample(t0.Add(time.Duration(i) * time.Second))
	}
	// 200k hits × 500ns = 100ms of a 300ms target: 50% overhead, over 10%.
	cc, ch := step(1, 200_000, 300)
	if p := cc.Probes[0]; !p.OverheadKnown || p.OverheadPct < 49.9 || p.OverheadPct > 50.1 || len(ch) != 0 {
		t.Fatalf("window 1: overhead %v (%v), changes %v", p.OverheadPct, p.OverheadKnown, ch)
	}
	step(2, 200_000, 300)
	// Back under the budget: 2k hits = 1ms of a 300ms target.
	if _, ch := step(3, 2_000, 300); len(ch) != 0 {
		t.Fatal("detached without three windows in a row")
	}
	step(4, 200_000, 300)
	step(5, 200_000, 300)
	_, ch = step(6, 200_000, 300)
	if len(ch) != 1 || ch[0].Status.Name != "heap" || ch[0].Status.State != ProbeDisabled || len(detached) != 1 {
		t.Fatalf("three windows over: changes %+v, detached %v", ch, detached)
	}
	// Detached: no more estimates for it, and no second detach.
	if cc, ch := step(7, 200_000, 300); len(cc.Probes) != 0 || len(ch) != 0 || len(detached) != 1 {
		t.Errorf("after the detach: probes %+v, changes %v, detached %v", cc.Probes, ch, detached)
	}
}

// A target whose CPU in the window is no more than the estimate (ticks of 10ms)
// gives no overhead, and an unknown overhead never counts toward the budget.
func TestOverheadUnknownDoesNotCount(t *testing.T) {
	src := &fakeCostSource{}
	c := NewCostCollector(map[string]CostSource{"heap": src}).WithBudget(1, func(string, string) error {
		t.Fatal("detached on an unknown overhead")
		return nil
	})
	c.trap = bpf.UprobeTrapCost{EntryNs: 500}
	c.targetCPU = func() (time.Duration, bool) { return 0, true }
	c.sample(time.Unix(100, 0))
	for i := 1; i <= 5; i++ {
		src.c.Entries += 200_000
		cc, _ := c.sample(time.Unix(100+int64(i), 0))
		if cc.Probes[0].OverheadKnown {
			t.Fatalf("window %d: overhead known with no target CPU", i)
		}
	}
}
