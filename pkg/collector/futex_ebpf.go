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

// FutexEBPFCollector consumes the futex_stats map periodically and publishes
// a []LockEntry ranked by contention in the current window (delta of
// waits in the last interval). Emits TimelineEvent category="lock" when
// some lock passes the contention threshold for the interval.
//
// The kernel counts waits per (futex word, contention site), so each lock is
// named by the call site doing most of the blocking (#89) — an identity that
// survives ASLR, unlike the futex word address. Symbolization needs one
// process's memory map, so in cgroup mode (a subtree of processes) the sites
// stay unresolved and only the address is reported.
type FutexEBPFCollector struct {
	tracer *bpf.FutexTracer
	sym    *symbol.Symbolizer // nil in cgroup mode, or if /proc maps failed
	ch     chan interface{}
	stop   chan struct{}

	mu         sync.Mutex
	prev       map[uint64]uint64        // uaddr → cumulative waits last window
	siteCache  map[int32]lockSite       // stack_id → resolved contention site
	stackCache map[int32][]symbol.Frame // stack_id → full leaf-first frames
}

// contentionThreshold defines how many new waits in the interval (1s) are
// enough to emit a TimelineEvent. Small enough to detect problematic
// locks, large enough to ignore "ok" mutexes that occasionally block.
const contentionThreshold = 20

// topLockEntries is how many rows the LockGraph publishes. F4 has a small
// footprint; keep it compact.
const topLockEntries = 8

func NewFutexEBPFCollector() *FutexEBPFCollector {
	return &FutexEBPFCollector{
		ch:         make(chan interface{}, 8),
		stop:       make(chan struct{}),
		prev:       make(map[uint64]uint64),
		siteCache:  make(map[int32]lockSite),
		stackCache: make(map[int32][]symbol.Frame),
	}
}

func (c *FutexEBPFCollector) Start(pid int) error { return c.start(bpf.TargetPID(pid), pid) }

// StartCgroup tracks futex contention across a whole cgroup subtree instead of
// one pid (#94). Implements CgroupTargeter. Contention sites stay unresolved:
// symbolization reads one process's memory map, and a subtree has no single
// process to read.
func (c *FutexEBPFCollector) StartCgroup(spec string) error {
	return c.start(bpf.TargetCgroup(spec), 0)
}

func (c *FutexEBPFCollector) start(t bpf.Target, pid int) error {
	tracer, err := bpf.OpenFutexTracer(t)
	if err != nil {
		return fmt.Errorf("futex eBPF: %w", err)
	}
	c.tracer = tracer
	// Symbolize best-effort: without /proc maps the sites degrade to the bare
	// address, exactly as before #89 — never fail Start over it.
	if pid <= 0 {
		c.sym = nil
	} else if sym, err := symbol.NewSymbolizer(pid); err == nil {
		c.sym = sym
	} else {
		fmt.Fprintf(os.Stderr, "futex: call-site symbolization unavailable for pid %d: %v\n", pid, err)
	}
	go c.loop()
	return nil
}

func (c *FutexEBPFCollector) Stop() {
	close(c.stop)
	if c.tracer != nil {
		_ = c.tracer.Close()
		c.tracer = nil
	}
	if c.sym != nil {
		_ = c.sym.Close()
		c.sym = nil
	}
}

func (c *FutexEBPFCollector) Subscribe() <-chan interface{} {
	return c.ch
}

// ResolveStack returns the full leaf-first symbolized frames of a captured
// contention stack, or ok=false when the id is unknown (wake-path sentinel,
// evicted from the kernel map, or empty). Results are cached (stacks are
// immutable for the process lifetime). Safe for concurrent use — the headless
// server calls it from gRPC handlers while the publish loop runs. Backs the
// EventStreamService.ResolveStack RPC for LockEntry.stack_id (#54/#89).
func (c *FutexEBPFCollector) ResolveStack(stackID uint64) ([]symbol.Frame, bool) {
	if c.tracer == nil || int32(stackID) < 0 {
		return nil, false
	}
	sid := int32(stackID)
	c.mu.Lock()
	if fr, ok := c.stackCache[sid]; ok {
		c.mu.Unlock()
		return fr, true
	}
	c.mu.Unlock()

	addrs, err := c.tracer.ResolveStack(sid)
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
// per-process key for the stack ids this collector hands out. "" in cgroup mode
// or when the target has no build-id.
func (c *FutexEBPFCollector) ProcessBuildID() string {
	if c.sym == nil {
		return ""
	}
	return c.sym.ProcessBuildID()
}

func (c *FutexEBPFCollector) loop() {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			snap, hot := c.snapshot()
			select {
			case c.ch <- snap:
			default:
			}
			// Timeline events: one per "hot" lock in the interval.
			// Cap at 3 per tick to avoid flooding.
			emitted := 0
			for _, e := range hot {
				if emitted >= 3 {
					break
				}
				select {
				case c.ch <- TimelineEvent{
					Timestamp: time.Now(),
					Category:  "lock",
					Message: fmt.Sprintf(
						"%s ↑ %d waits (avg %.1fms, last tid %d)",
						lockName(e), e.WaitDelta, e.LatencyMs, e.LastWaitTID,
					),
				}:
					emitted++
				default:
				}
			}
		}
	}
}

// snapshot reads futex_stats, folds the per-site rows into one entry per lock,
// computes the window delta vs the previous read and returns the top-N by
// contention plus the "hot" list (those past the threshold for a timeline
// event). Only the entries actually published get their call site symbolized.
func (c *FutexEBPFCollector) snapshot() (snap []LockEntry, hot []LockEntry) {
	if c.tracer == nil {
		return nil, nil
	}
	stats, err := c.tracer.Stats()
	if err != nil {
		return nil, nil
	}

	samples := make([]lockSample, 0, len(stats))
	for k, s := range stats {
		samples = append(samples, lockSample{
			UAddr:       k.UAddr,
			StackID:     k.StackID,
			WaitCount:   s.WaitCount,
			WakeCount:   s.WakeCount,
			LatSumNs:    s.LatSumNs,
			LatCount:    s.LatCount,
			LastWaitTID: int(s.LastWaitTID),
			LastWakeTID: int(s.LastWakeTID),
		})
	}

	c.mu.Lock()
	entries, cur := aggregateLocks(samples, c.prev)
	c.prev = cur
	c.mu.Unlock()

	ranked := rankLocks(entries, -1)
	hotN := countHot(ranked, contentionThreshold)

	// Everything published is either in the top-N or hot, and rankLocks sorts
	// by window delta first, so both are prefixes of ranked.
	resolveN := topLockEntries
	if hotN > resolveN {
		resolveN = hotN
	}
	if resolveN > len(ranked) {
		resolveN = len(ranked)
	}
	for i := range ranked[:resolveN] {
		c.attachSite(&ranked[i])
	}

	snap = ranked[:min(topLockEntries, len(ranked))]
	return snap, ranked[:hotN]
}

// attachSite fills e's call-site fields from its dominant contention stack.
// A lock whose stack walk failed keeps StackID < 0 and zeroed site fields.
func (c *FutexEBPFCollector) attachSite(e *LockEntry) {
	if e.StackID < 0 {
		return
	}
	site := c.resolveSite(e.StackID)
	e.CallSite = site.addr
	e.Func = site.frame.Func
	e.File = site.frame.File
	e.Line = site.frame.Line
	e.Module = site.frame.Module
	e.Offset = site.frame.Offset
}

// resolveSite maps a stack_id to the application frame that blocked on the
// futex, via pickLockSite (which walks past the locking machinery and, finding
// nothing else, reports the address alone rather than a name every lock in the
// process shares — #107). Cached under c.mu, since stacks are stable for the
// process lifetime and symbolizing re-reads ELF modules. Returns a zero site
// when the stack walk failed or nothing could be read.
func (c *FutexEBPFCollector) resolveSite(stackID int32) lockSite {
	if stackID < 0 || c.tracer == nil {
		return lockSite{}
	}
	c.mu.Lock()
	if s, ok := c.siteCache[stackID]; ok {
		c.mu.Unlock()
		return s
	}
	c.mu.Unlock()

	frames, err := c.tracer.ResolveStack(stackID)
	if err != nil || len(frames) == 0 {
		return lockSite{}
	}
	// nil resolver in cgroup mode: a subtree has no single memory map to
	// resolve against, so its sites stay addresses.
	var resolve func(uint64) symbol.Frame
	if c.sym != nil {
		resolve = c.sym.Symbolize
	}
	site := pickLockSite(frames, resolve)

	c.mu.Lock()
	c.siteCache[stackID] = site
	c.mu.Unlock()
	return site
}
