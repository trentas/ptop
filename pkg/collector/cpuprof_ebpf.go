//go:build linux && ebpf

package collector

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/trentas/ptop/internal/bpf"
	"github.com/trentas/ptop/pkg/symbol"
)

// CPUProfEBPFCollector publishes a CPUProfile every window: which functions the
// sampler caught the target executing, and how many samples each one took
// (#125).
//
// It is the WHERE axis. CPUEBPFCollector publishes the HOW MUCH axis from the
// same subsystem's scheduler accounting, and the two are deliberately separate
// collectors publishing separate values — a magnitude that is exact and an
// attribution that is an estimate should never be reachable through one field.
// See programs/cpuprof.bpf.c.
//
// No /proc fallback exists and none is possible: nothing outside the kernel can
// tell you which function a process was in.
type CPUProfEBPFCollector struct {
	prof *bpf.CPUProfiler
	sym  *symbol.Symbolizer // nil when /proc maps could not be parsed
	syms *symbol.Debuginfod // optional off-ELF symbol source (#119)
	hz   int
	ch   chan interface{}
	stop chan struct{}
	pid  int

	mu         sync.Mutex
	siteCache  map[int32]rawCPUSite     // stack_id → resolved leaf (cache)
	stackCache map[int32][]symbol.Frame // stack_id → full leaf-first frames
	lastAt     time.Time                // publishLoop-only: window baseline
	lastFired  uint64                   // publishLoop-only: delivered samples
}

const (
	// cpuProfTopSites matches heapTopCallSites: the list is a top-N and the
	// omitted totals are what make its truncation readable.
	cpuProfTopSites = 8

	// cpuProfPublishInterval matches the CPU magnitude axis's cadence, so a
	// consumer lines the two up without resampling. At the default rate a busy
	// core contributes ~99 samples to a window, which is a usable top-N; a
	// nearly idle target contributes a handful, and TotalSamples is what says
	// so rather than the list pretending otherwise.
	cpuProfPublishInterval = time.Second
)

// NewCPUProfEBPFCollector builds the collector at hz samples per second per
// CPU. syms is the optional off-ELF symbol source (#119); nil resolves from the
// mapped image alone.
func NewCPUProfEBPFCollector(hz int, syms *symbol.Debuginfod) *CPUProfEBPFCollector {
	return &CPUProfEBPFCollector{
		hz:         hz,
		syms:       syms,
		ch:         make(chan interface{}, 16),
		stop:       make(chan struct{}),
		siteCache:  make(map[int32]rawCPUSite),
		stackCache: make(map[int32][]symbol.Frame),
	}
}

// Start attaches the sampler to one process.
//
// PID mode only, and not a CgroupTargeter: the kernel filter would work over a
// subtree, but the aggregate would not. Sites are folded by function, which is
// resolved against ONE process's memory map — across a subtree the same address
// is a different function in every process, so folding them would not be
// unresolved, it would be wrong. See cgroupUnsupported.
func (c *CPUProfEBPFCollector) Start(pid int) error {
	prof, err := bpf.OpenCPUProfiler(bpf.TargetPID(pid), c.hz)
	if err != nil {
		return fmt.Errorf("cpuprof eBPF: %w", err)
	}
	c.prof = prof
	c.pid = pid

	// Symbolization is what this axis is FOR, but a failure still must not
	// fail Start: without it the sites come out as module+offset, which is
	// less than the point and more than nothing.
	if sym, err := symbol.NewSymbolizer(pid, symbol.WithDebuginfod(c.syms)); err == nil {
		c.sym = sym
	} else {
		fmt.Fprintf(os.Stderr, "cpuprof: symbolization unavailable for pid %d: %v\n", pid, err)
	}

	// Baseline now rather than on the first tick, so the first published
	// window covers the time since attach instead of since process start.
	if _, err := c.prof.Samples(); err != nil {
		fmt.Fprintf(os.Stderr, "cpuprof: clearing the initial window: %v\n", err)
	}
	if r, err := c.prof.Rate(); err == nil {
		c.lastFired = r.Fired
	}
	c.lastAt = time.Now()

	go c.publishLoop()
	return nil
}

func (c *CPUProfEBPFCollector) Stop() {
	close(c.stop)
	if c.prof != nil {
		_ = c.prof.Close()
		c.prof = nil
	}
}

func (c *CPUProfEBPFCollector) Subscribe() <-chan interface{} { return c.ch }

func (c *CPUProfEBPFCollector) publishLoop() {
	t := time.NewTicker(cpuProfPublishInterval)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			p, err := c.snapshot()
			if err != nil {
				continue
			}
			publish(c.ch, p)
		}
	}
}

// snapshot drains the window's samples and turns them into a CPUProfile.
//
// It publishes even when the window is empty. A target that used no CPU took no
// samples, and saying so — TotalSamples 0, no sites — is a measurement; going
// silent would leave a consumer unable to tell an idle process from a collector
// that stopped.
func (c *CPUProfEBPFCollector) snapshot() (CPUProfile, error) {
	if c.prof == nil {
		return CPUProfile{}, fmt.Errorf("profiler not open")
	}
	samples, err := c.prof.Samples()
	if err != nil {
		return CPUProfile{}, err
	}
	rate, err := c.prof.Rate()
	if err != nil {
		return CPUProfile{}, err
	}

	now := time.Now()
	window := now.Sub(c.lastAt)
	firedDelta := rate.Fired - c.lastFired
	c.lastAt, c.lastFired = now, rate.Fired

	raw := make([]rawCPUSite, 0, len(samples))
	var total uint64
	for sid, n := range samples {
		total += n
		raw = append(raw, c.resolveSite(sid, n))
	}
	sites, unresolved := foldCPUSites(raw)
	top, omitted := topCPUSites(sites, cpuProfTopSites)

	return CPUProfile{
		Timestamp:         now,
		Sites:             withCPUShares(top, total),
		TotalSamples:      total,
		UnresolvedSamples: unresolved,
		WindowMs:          uint64(window.Milliseconds()),
		SampleRateHz:      achievedHz(firedDelta, window.Seconds(), c.prof.NumCPU()),
		RequestedRateHz:   float64(c.prof.RequestedHz()),
		TotalSites:        uint32(len(sites)),
		OmittedSamples:    omitted.Samples,
	}, nil
}

// resolveSite resolves one stack id to its LEAF frame — the function that was
// executing — and caches it. Stacks are immutable for the process lifetime, and
// the cache is also what keeps ResolveStack answering for a site after the
// kernel's stack map has evicted it.
//
// No walking past machinery here, unlike the heap axis (pickAppFrame) and the
// lock axis (pickLockSite). Those walk because the allocator and the futex
// wrapper are the mechanism rather than the destination. On this axis the leaf
// IS the answer: if the target is in runtime.memmove, that is where its CPU
// went, and a consumer that wants to attribute it to a caller has StackID.
func (c *CPUProfEBPFCollector) resolveSite(stackID int32, samples uint64) rawCPUSite {
	c.mu.Lock()
	cached, ok := c.siteCache[stackID]
	c.mu.Unlock()
	if ok {
		cached.Samples = samples
		return cached
	}

	site := rawCPUSite{StackID: stackID, Samples: samples}
	frames, err := c.prof.ResolveStack(stackID)
	if err == nil {
		for _, f := range frames {
			if f == 0 {
				continue
			}
			site.Addr = f
			break
		}
	}
	if c.sym != nil && site.Addr != 0 {
		site.Frame = c.sym.Symbolize(site.Addr)
	}

	c.mu.Lock()
	c.siteCache[stackID] = site
	c.mu.Unlock()
	return site
}

// ResolveStack returns the full leaf-first symbolized frames of a captured
// stack id, or ok=false when the id is unknown. Backs the
// EventStreamService.ResolveStack RPC for this source (#54/#89); safe for
// concurrent use.
func (c *CPUProfEBPFCollector) ResolveStack(stackID uint64) ([]symbol.Frame, bool) {
	if c.prof == nil || int32(stackID) < 0 {
		return nil, false
	}
	sid := int32(stackID)
	c.mu.Lock()
	if fr, ok := c.stackCache[sid]; ok {
		c.mu.Unlock()
		return fr, true
	}
	c.mu.Unlock()

	addrs, err := c.prof.ResolveStack(sid)
	if err != nil || len(addrs) == 0 {
		return nil, false
	}
	frames := make([]symbol.Frame, len(addrs))
	for i, a := range addrs {
		if c.sym != nil {
			frames[i] = c.sym.Symbolize(a)
		} else {
			frames[i] = symbol.Frame{Offset: a}
		}
	}

	c.mu.Lock()
	c.stackCache[sid] = frames
	c.mu.Unlock()
	return frames, true
}

// ProcessBuildID returns the target executable's GNU build-id — the stable
// cache key for the stack ids this collector hands out. "" when there is none.
func (c *CPUProfEBPFCollector) ProcessBuildID() string {
	if c.sym == nil {
		return ""
	}
	return c.sym.ProcessBuildID()
}
