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
	first := c.sample(t0)
	if first.PtopKnown || len(first.Probes) != 0 {
		t.Fatalf("the first sample has no window: %+v", first)
	}

	// One second: 1M entries and 1M returns, 31,250 of the 2M hits timed at
	// 100ns each.
	src.c = bpf.ProbeCostCounters{Entries: 1_000_000, Returns: 1_000_000, Timed: 31_250, TimedNs: 3_125_000}
	got := c.sample(t0.Add(time.Second))
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
	p = c.sample(t0.Add(2 * time.Second)).Probes[0]
	if p.Entries != 100 || p.ProgramNs != 100 || math.Abs(p.EstimatePct-0.006) > 1e-9 {
		t.Errorf("quiet window = %+v, want 100 entries at 600ns", p)
	}
}

// With no probe to measure, the capture still says what ptop itself costs.
func TestCostWithoutProbes(t *testing.T) {
	c := NewCostCollector(nil)
	c.sample(time.Unix(100, 0))
	got := c.sample(time.Unix(101, 0))
	if !got.PtopKnown || got.PtopCPUPct < 0 || len(got.Probes) != 0 {
		t.Errorf("no-probe sample = %+v", got)
	}
}
