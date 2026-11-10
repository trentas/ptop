package collector

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/trentas/ptop/internal/bpf"
)

// ─── What the capture costs (#154) ───────────────────────────────────────────
//
// The cost table in the README is measured and honest, and it is read once,
// before the capture. The heap probe's cost is not a constant: it is a per-hit
// cost times the target's allocation rate, which ptop observes live. So every
// second the capture says what it is costing: an estimate of the CPU each
// uprobe charged to the target's threads, with the basis it was computed
// from, and ptop's own CPU beside it.

// CaptureCost is the capture's cost over one window.
type CaptureCost struct {
	Timestamp time.Time
	// PtopCPUPct is ptop's own CPU over the window, as % of one core: the
	// observer's cost to the host, not to the target. PtopKnown is false on
	// the first sample, which has no window.
	PtopCPUPct float64
	PtopKnown  bool
	Probes     []ProbeCost
}

// ProbeCost is one uprobe's estimated cost to the target's threads over the
// window. EstimatePct is % of one core:
//
//	(Entries + Returns) × ProgramNs + Entries × TrapEntryNs + Returns × TrapReturnNs
//
// ProgramNs is measured in the kernel on one hit in 64; the trap costs are
// calibrated on this host at startup (Calibration says how). An estimate,
// published with its basis, not a measured overhead.
type ProbeCost struct {
	Probe                     string
	EstimatePct               float64
	Entries, Returns          uint64
	ProgramNs                 float64
	TrapEntryNs, TrapReturnNs float64
	Calibration               string
}

// CostSource is a probe whose hits CostCollector can read. The heap collector
// is the only one: every other probe fires on kernel events and costs nothing
// measurable (README, "What it costs").
type CostSource interface {
	ProbeCost() (bpf.ProbeCostCounters, error)
}

// costInterval matches the other windows.
const costInterval = time.Second

// CostCollector publishes a CaptureCost every costInterval. It is context, like
// ProcContext: it measures the observer, not the target, and has no --disable
// name. A Set with no heap probe still reports ptop's own CPU.
type CostCollector struct {
	sources map[string]CostSource
	ch      chan interface{}
	stop    chan struct{}
	once    sync.Once

	trap        bpf.UprobeTrapCost
	calibration string

	prev      map[string]bpf.ProbeCostCounters
	programNs map[string]float64 // last known, for windows that timed no hit
	prevCPU   time.Duration
	prevAt    time.Time
}

func NewCostCollector(sources map[string]CostSource) *CostCollector {
	return &CostCollector{
		sources:   sources,
		ch:        make(chan interface{}, 4),
		stop:      make(chan struct{}),
		prev:      make(map[string]bpf.ProbeCostCounters),
		programNs: make(map[string]float64),
	}
}

// Start begins publishing. The pid is not used: what is measured is ptop and
// the probes it holds.
func (c *CostCollector) Start(int) error {
	go c.loop()
	return nil
}

func (c *CostCollector) Stop()                         { c.once.Do(func() { close(c.stop) }) }
func (c *CostCollector) Subscribe() <-chan interface{} { return c.ch }

func (c *CostCollector) loop() {
	if len(c.sources) > 0 {
		c.calibrate()
	}
	publish(c.ch, c.sample(time.Now()))
	t := time.NewTicker(costInterval)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case now := <-t.C:
			publish(c.ch, c.sample(now))
		}
	}
}

func (c *CostCollector) calibrate() {
	trap, err := bpf.CalibrateUprobeTraps()
	if err != nil {
		c.calibration = fmt.Sprintf("trap cost not calibrated (%v): the estimate is the program time alone, a floor", err)
		return
	}
	c.trap = trap
	c.calibration = fmt.Sprintf("empty uprobe and uretprobe on a ptop function, %d calls, fastest of 5 rounds", trap.Calls)
}

func (c *CostCollector) sample(now time.Time) CaptureCost {
	out := CaptureCost{Timestamp: now}
	window := now.Sub(c.prevAt)
	first := c.prevAt.IsZero()
	if cpu, ok := selfCPU(); ok {
		if !first && window > 0 {
			out.PtopCPUPct, out.PtopKnown = float64(cpu-c.prevCPU)/float64(window)*100, true
		}
		c.prevCPU = cpu
	}
	names := make([]string, 0, len(c.sources))
	for name := range c.sources {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		cur, err := c.sources[name].ProbeCost()
		if err != nil {
			continue
		}
		prev, seen := c.prev[name]
		c.prev[name] = cur
		if !seen || first || window <= 0 {
			continue
		}
		out.Probes = append(out.Probes, c.estimate(name, prev, cur, window))
	}
	c.prevAt = now
	return out
}

func (c *CostCollector) estimate(name string, prev, cur bpf.ProbeCostCounters, window time.Duration) ProbeCost {
	entries, returns := cur.Entries-prev.Entries, cur.Returns-prev.Returns
	if timed := cur.Timed - prev.Timed; timed > 0 {
		c.programNs[name] = float64(cur.TimedNs-prev.TimedNs) / float64(timed)
	}
	p := ProbeCost{
		Probe:        name,
		Entries:      entries,
		Returns:      returns,
		ProgramNs:    c.programNs[name],
		TrapEntryNs:  c.trap.EntryNs,
		TrapReturnNs: c.trap.ReturnNs,
		Calibration:  c.calibration,
	}
	ns := float64(entries+returns)*p.ProgramNs + float64(entries)*p.TrapEntryNs + float64(returns)*p.TrapReturnNs
	p.EstimatePct = ns / float64(window) * 100
	return p
}

// selfCPU is ptop's own user + system CPU time so far.
func selfCPU() (time.Duration, bool) {
	var ru unix.Rusage
	if unix.Getrusage(unix.RUSAGE_SELF, &ru) != nil {
		return 0, false
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano()), true
}
