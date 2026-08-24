//go:build linux && ebpf

package collector

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trentas/ptop/internal/bpf"
	"github.com/trentas/ptop/pkg/symbol"
)

// HeapEBPFCollector tracks heap allocations via uprobes (#53). Two goroutines:
//
//   - readLoop drains the per-event ring buffer, forwarding each event as a
//     HeapEvent (best-effort, dropped under backpressure like every other
//     collector). On the libc lane it also counts allocations for the rate; on
//     the Go lane the rate comes from the kernel's own totals, because the
//     events there are sampled (see ratesGo).
//   - publishLoop, every 500ms, reads the kernel's per-call-site aggregate and
//     publishes a HeapStats snapshot.
//
// ─── Two lanes, chosen by what the target actually allocates through ────────
//
// HeapLaneLibc attaches to malloc/calloc/realloc/free and pairs each
// allocation with its free, so it measures live bytes and lifetimes. Those
// figures come from the kernel's LRU-bounded live set, so they UNDERCOUNT on
// alloc-heavy targets (documented in heap.bpf.c) — never presented as exact.
//
// HeapLaneGo attaches to runtime.mallocgc. A Go process does not allocate
// through libc at all, so on the libc lane its call-site axis comes back
// EMPTY — and that axis is the only part of the signature carrying
// func/file/line, so an entire runtime family loses the behaviour → code link.
// The Go lane measures allocation rate and volume per site and reports
// LiveMeasured=false, because nothing frees at a point a probe can observe
// (see goalloc.bpf.c).
//
// The Go lane is preferred whenever the target is a Go image, including a cgo
// build with libc mapped: the Go allocator is where a Go program's allocations
// overwhelmingly are, and running both lanes at once would pay for two probe
// sets to produce one axis with two incompatible definitions of "live".
type HeapEBPFCollector struct {
	tracer   *bpf.HeapTracer    // libc lane; nil on the Go lane
	goTracer *bpf.GoAllocTracer // Go lane; nil on the libc lane
	lane     string             // HeapLaneLibc | HeapLaneGo
	sym      *symbol.Symbolizer // nil if /proc maps couldn't be parsed
	ch       chan interface{}
	stop     chan struct{}
	pid      int

	// sampleBytes is the Go lane's stack-sampling rate: bytes of allocation
	// between recorded samples (#108). A rate of 1 records every allocation
	// (HeapSampleEveryAllocation). The libc lane ignores it — it pairs alloc
	// with free to track a live set, and sampling would leave frees with no
	// allocation to pair against.
	sampleBytes uint64

	leakThreshold time.Duration

	// libc lane only: allocations/bytes since the last publish, fed by
	// readLoop. The Go lane reads its totals from the kernel instead — see
	// ratesGo.
	allocCount uint64 // atomic
	allocBytes uint64 // atomic

	mu         sync.Mutex
	siteCache  map[int32]heapSite       // stack_id → resolved app call-site (cache)
	stackCache map[int32][]symbol.Frame // stack_id → full leaf-first frames (cache)
	lastAt     time.Time                // publishLoop-only; rate baseline
	// Go lane only: the kernel's cumulative allocation totals as of the last
	// publish. publishLoop-only, like lastAt.
	lastTotalCount uint64
	lastTotalBytes uint64
}

// heapSite is the resolved application call site for a stack_id: the raw frame
// address plus its symbolization. Cached because stacks are stable for the
// process lifetime and symbolizing re-reads ELF modules.
type heapSite struct {
	addr  uint64
	frame symbol.Frame
}

const (
	heapDefaultLeakThreshold = 10 * time.Second
	heapTopCallSites         = 8
	heapPublishInterval      = 500 * time.Millisecond
)

// NewHeapEBPFCollector builds the collector with sampleBytes as the Go lane's
// stack-sampling rate — bpf.GoAllocDefaultSampleBytes is the usual value, and
// HeapSampleEveryAllocation records every allocation, exact and expensive (see
// goalloc.bpf.c). Callers holding a SetConfig should go through
// heapSampleBytes, which fills in the default.
func NewHeapEBPFCollector(sampleBytes uint64) *HeapEBPFCollector {
	return &HeapEBPFCollector{
		ch:            make(chan interface{}, 64),
		stop:          make(chan struct{}),
		sampleBytes:   sampleBytes,
		leakThreshold: heapDefaultLeakThreshold,
		siteCache:     make(map[int32]heapSite),
		stackCache:    make(map[int32][]symbol.Frame),
	}
}

func (c *HeapEBPFCollector) Start(pid int) error {
	// Try the Go lane first and fall back on ErrNotGo. The reverse order does
	// not work: a Go binary built with cgo HAS a libc mapped, so the libc
	// tracer attaches happily and then reports an empty axis forever — a
	// silent wrong answer, which is worse than a loud missing one.
	goTracer, err := bpf.OpenGoAllocTracer(pid, c.sampleBytes)
	switch {
	case err == nil:
		c.goTracer, c.lane = goTracer, HeapLaneGo
	case errors.Is(err, bpf.ErrNotGo):
		tracer, lerr := bpf.OpenHeapTracer(pid)
		if lerr != nil {
			return fmt.Errorf("heap eBPF: %w", lerr)
		}
		c.tracer, c.lane = tracer, HeapLaneLibc
	default:
		return fmt.Errorf("heap eBPF (go lane): %w", err)
	}
	c.pid = pid
	// Symbolize call sites best-effort: without /proc maps (or off Linux) the
	// sites degrade to hex, exactly as before #54 — never fail Start over it.
	if sym, err := symbol.NewSymbolizer(pid); err == nil {
		c.sym = sym
	} else {
		fmt.Fprintf(os.Stderr, "heap: call-site symbolization unavailable for pid %d: %v\n", pid, err)
	}
	go c.readLoop()
	go c.publishLoop()
	return nil
}

func (c *HeapEBPFCollector) Stop() {
	close(c.stop)
	if c.tracer != nil {
		_ = c.tracer.Close()
		c.tracer = nil
	}
	if c.goTracer != nil {
		_ = c.goTracer.Close()
		c.goTracer = nil
	}
	if c.sym != nil {
		_ = c.sym.Close()
		c.sym = nil
	}
}

func (c *HeapEBPFCollector) Subscribe() <-chan interface{} { return c.ch }

func (c *HeapEBPFCollector) readLoop() {
	if c.lane == HeapLaneGo {
		c.readLoopGo()
		return
	}
	c.readLoopLibc()
}

func (c *HeapEBPFCollector) readLoopLibc() {
	for {
		ev, err := c.tracer.Next()
		if err != nil {
			if err == io.EOF {
				return
			}
			continue // transient; keep reading
		}
		if ev.Op != bpf.HeapOpFree {
			atomic.AddUint64(&c.allocCount, 1)
			atomic.AddUint64(&c.allocBytes, ev.Size)
		}
		he := HeapEvent{
			Op:         heapOpName(ev.Op),
			Size:       ev.Size,
			Addr:       ev.Addr,
			LifetimeMs: float64(ev.LifetimeNs) / 1e6,
			CallSite:   c.resolveSite(ev.StackID).addr,
			StackID:    ev.StackID,
			Large:      ev.Flags&bpf.HeapFlagLarge != 0,
			// The libc lane observes every call, so an event stands for itself.
			WeightCount: 1,
			WeightBytes: ev.Size,
		}
		select {
		case c.ch <- he:
		default:
		}
	}
}

// readLoopGo drains the Go allocation ring buffer. Every event is an
// allocation — the lane emits no free, and Addr stays 0 because the entry
// probe runs before mallocgc has an address to return (see goalloc.bpf.c on
// why there is no return probe).
func (c *HeapEBPFCollector) readLoopGo() {
	for {
		ev, err := c.goTracer.Next()
		if err != nil {
			if err == io.EOF {
				return
			}
			continue // transient; keep reading
		}
		// No rate counting here: the Go lane's rate comes from the kernel's
		// per-CPU totals, which count every allocation whether or not it was
		// sampled and whatever the ring buffer dropped (see ratesGo).
		he := HeapEvent{
			Op:          "alloc",
			Size:        ev.Size,
			CallSite:    c.resolveSite(ev.StackID).addr,
			StackID:     ev.StackID,
			Large:       ev.Flags&bpf.GoAllocFlagLarge != 0,
			WeightCount: ev.WeightCount,
			WeightBytes: ev.WeightBytes,
		}
		select {
		case c.ch <- he:
		default:
		}
	}
}

// resolveSite maps a stack_id to its application call site (address + symbol),
// caching the result (stacks are stable for the process lifetime). Concurrent
// callers (readLoop + publishLoop) share the cache under c.mu.
func (c *HeapEBPFCollector) resolveSite(stackID int32) heapSite {
	if stackID < 0 {
		return heapSite{}
	}
	c.mu.Lock()
	if s, ok := c.siteCache[stackID]; ok {
		c.mu.Unlock()
		return s
	}
	c.mu.Unlock()

	frames, err := c.stackFrames(stackID)
	if err != nil {
		return heapSite{}
	}

	var addr uint64
	if c.lane == HeapLaneGo {
		// The runtime and the application are one module here, so the app
		// frame is found by function name, not by address range.
		addr = pickGoAppFrame(frames, c.funcNameAt)
	} else {
		lo, hi := c.tracer.LibcRange()
		addr = pickAppFrame(frames, lo, hi)
	}
	site := heapSite{addr: addr}
	if c.sym != nil && site.addr != 0 {
		site.frame = c.sym.Symbolize(site.addr)
	}

	c.mu.Lock()
	c.siteCache[stackID] = site
	c.mu.Unlock()
	return site
}

// stackFrames reads the raw leaf-first stack for stackID from whichever lane
// is active.
func (c *HeapEBPFCollector) stackFrames(stackID int32) ([]uint64, error) {
	if c.lane == HeapLaneGo {
		return c.goTracer.ResolveStack(stackID)
	}
	return c.tracer.ResolveStack(stackID)
}

// funcNameAt resolves a frame address to its function name, or "" when there
// is no symbolizer or the address does not resolve. Used to tell Go runtime
// frames from application frames.
func (c *HeapEBPFCollector) funcNameAt(addr uint64) string {
	if c.sym == nil {
		return ""
	}
	return c.sym.Symbolize(addr).Func
}

// ResolveStack returns the full leaf-first symbolized frames of a captured
// stack id, or ok=false when the id is unknown (negative sentinel, evicted from
// the kernel map, or empty). Results are cached (stacks are immutable for the
// process lifetime). Safe for concurrent use — the headless server calls it
// from gRPC handlers while readLoop/publishLoop run. Implements the resolver the
// EventStreamService.ResolveStack RPC is built on (#54).
func (c *HeapEBPFCollector) ResolveStack(stackID uint64) ([]symbol.Frame, bool) {
	if (c.tracer == nil && c.goTracer == nil) || int32(stackID) < 0 {
		return nil, false
	}
	sid := int32(stackID)
	c.mu.Lock()
	if fr, ok := c.stackCache[sid]; ok {
		c.mu.Unlock()
		return fr, true
	}
	c.mu.Unlock()

	addrs, err := c.stackFrames(sid)
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

// ProcessBuildID returns the target executable's GNU build-id — a stable key
// for the stack ids this collector hands out (see symbol.Symbolizer). "" when
// the process has no build-id or no symbolizer was built.
func (c *HeapEBPFCollector) ProcessBuildID() string {
	if c.sym == nil {
		return ""
	}
	return c.sym.ProcessBuildID()
}

func (c *HeapEBPFCollector) publishLoop() {
	t := time.NewTicker(heapPublishInterval)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			if s, err := c.snapshot(); err == nil {
				select {
				case c.ch <- s:
				default:
				}
			}
		}
	}
}

func (c *HeapEBPFCollector) snapshot() (HeapStats, error) {
	if c.lane == HeapLaneGo {
		return c.snapshotGo()
	}
	return c.snapshotLibc()
}

// snapshotGo builds a HeapStats from the Go allocation aggregate. It fills
// only what mallocgc can tell us — count and bytes per site — and leaves
// LiveHeapBytes, LiveBytes, AvgLifetimeMs, SuspectedLeakBytes and Suspected at
// their zero values, flagged by LiveMeasured=false so a consumer cannot
// mistake "not measured" for "measured, and zero".
func (c *HeapEBPFCollector) snapshotGo() (HeapStats, error) {
	agg, err := c.goTracer.CallSites()
	if err != nil {
		return HeapStats{}, err
	}

	sites := make([]HeapCallSite, 0, len(agg))
	for sid, raw := range agg {
		site := c.resolveSite(sid)
		sites = append(sites, HeapCallSite{
			CallSite:   site.addr,
			AddrHex:    heapAddrHex(site.addr),
			Func:       site.frame.Func,
			File:       site.frame.File,
			Line:       site.frame.Line,
			Module:     site.frame.Module,
			Offset:     site.frame.Offset,
			StackID:    sid,
			AllocBytes: raw.AllocBytes,
			AllocCount: raw.AllocCount,
		})
	}

	now := time.Now()
	allocRate, byteRate := c.ratesGo(now)
	return HeapStats{
		Timestamp:      now,
		AllocRate:      allocRate,
		AllocBytesRate: byteRate,
		TopCallSites:   chooseTopCallSites(sites, heapTopCallSites),
		Lane:           HeapLaneGo,
		LiveMeasured:   false,
		SampleBytes:    sampledRate(c.goTracer.SampleBytes()),
	}, nil
}

func (c *HeapEBPFCollector) snapshotLibc() (HeapStats, error) {
	live, err := c.tracer.LiveCallSites()
	if err != nil {
		return HeapStats{}, err
	}
	leaks, err := c.tracer.LeakScan(uint64(c.leakThreshold.Nanoseconds()))
	if err != nil {
		return HeapStats{}, err
	}

	// Sum suspected-leak bytes by the alloc-site stack (same key the live
	// aggregate uses), so a call site can be flagged as leaking.
	leakBytes := make(map[int32]uint64, len(leaks))
	var suspectedTotal uint64
	for _, lk := range leaks {
		leakBytes[lk.StackID] += lk.Size
		suspectedTotal += lk.Size
	}

	sites := make([]HeapCallSite, 0, len(live))
	var liveTotal uint64
	for sid, raw := range live {
		lb := raw.LiveBytes
		if lb < 0 {
			lb = 0 // defensive: never present negative live bytes
		}
		liveTotal += uint64(lb)
		avgLifeMs := 0.0
		if raw.LifetimeCount > 0 {
			avgLifeMs = float64(raw.LifetimeSumNs) / float64(raw.LifetimeCount) / 1e6
		}
		site := c.resolveSite(sid)
		sites = append(sites, HeapCallSite{
			CallSite:      site.addr,
			AddrHex:       heapAddrHex(site.addr),
			Func:          site.frame.Func,
			File:          site.frame.File,
			Line:          site.frame.Line,
			Module:        site.frame.Module,
			Offset:        site.frame.Offset,
			StackID:       sid,
			LiveBytes:     uint64(lb),
			AllocCount:    raw.AllocCount,
			AllocBytes:    0, // the libc aggregate counts live bytes, not cumulative ones
			AvgLifetimeMs: avgLifeMs,
			Suspected:     leakBytes[sid] > 0,
		})
	}

	now := time.Now()
	rate, byteRate := c.rates(now)

	return HeapStats{
		Timestamp:          now,
		LiveHeapBytes:      liveTotal,
		AllocRate:          rate,
		AllocBytesRate:     byteRate,
		TopCallSites:       chooseTopCallSites(sites, heapTopCallSites),
		SuspectedLeakBytes: suspectedTotal,
		Lane:               HeapLaneLibc,
		LiveMeasured:       true,
	}, nil
}

// rates converts the counters readLoop has been accumulating into per-second
// figures and resets them. Libc lane only — the Go lane uses ratesGo.
//
// The first interval is discarded rather than reported: it spans process
// attach, so it would divide a partial count by a full interval and understate
// the rate at exactly the moment someone is watching the tool start up.
//
// publishLoop-only (c.lastAt is not guarded), matching the libc lane's
// original contract.
func (c *HeapEBPFCollector) rates(now time.Time) (allocRate, byteRate float64) {
	if c.lastAt.IsZero() {
		atomic.StoreUint64(&c.allocCount, 0)
		atomic.StoreUint64(&c.allocBytes, 0)
		c.lastAt = now
		return 0, 0
	}
	if elapsed := now.Sub(c.lastAt).Seconds(); elapsed > 0 {
		allocRate = float64(atomic.SwapUint64(&c.allocCount, 0)) / elapsed
		byteRate = float64(atomic.SwapUint64(&c.allocBytes, 0)) / elapsed
	}
	c.lastAt = now
	return allocRate, byteRate
}

// ratesGo is the Go lane's rate, read from the kernel's running totals rather
// than from the events readLoop saw. Two reasons it cannot come from the
// events: with sampling on, a target allocating less than one sample's worth
// per interval would report 0 and then a spike, and a ring buffer that
// overflowed would silently understate the rate for as long as it was full.
// The kernel counts every allocation on the way past, so neither shows up here.
//
// Like rates(), the first interval is discarded: it spans attach, and dividing
// a partial count by a full interval understates the rate exactly when someone
// is watching the tool start.
//
// publishLoop-only, same contract as rates().
func (c *HeapEBPFCollector) ratesGo(now time.Time) (allocRate, byteRate float64) {
	count, bytes, err := c.goTracer.Totals()
	if err != nil {
		return 0, 0
	}
	prevCount, prevBytes := c.lastTotalCount, c.lastTotalBytes
	c.lastTotalCount, c.lastTotalBytes = count, bytes

	if c.lastAt.IsZero() {
		c.lastAt = now
		return 0, 0
	}
	if elapsed := now.Sub(c.lastAt).Seconds(); elapsed > 0 {
		if count > prevCount {
			allocRate = float64(count-prevCount) / elapsed
		}
		if bytes > prevBytes {
			byteRate = float64(bytes-prevBytes) / elapsed
		}
	}
	c.lastAt = now
	return allocRate, byteRate
}
