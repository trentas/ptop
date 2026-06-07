//go:build linux && ebpf

package collector

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trentas/ptop/internal/bpf"
)

// HeapEBPFCollector tracks libc heap allocations via the uprobe-based eBPF
// tracer (#53). Two goroutines:
//
//   - readLoop drains the per-event ring buffer, forwarding each alloc/free as
//     a HeapEvent (best-effort, dropped under backpressure like every other
//     collector) and counting allocations for the rate.
//   - publishLoop, every 500ms, reads the kernel's per-call-site aggregate and
//     runs a bounded leak scan over the live set, publishing a HeapStats
//     snapshot.
//
// Live-heap and leak figures come from the kernel's LRU-bounded live set, so
// they UNDERCOUNT on alloc-heavy targets (documented in heap.bpf.c) — never
// presented as exact.
type HeapEBPFCollector struct {
	tracer *bpf.HeapTracer
	ch     chan interface{}
	stop   chan struct{}
	pid    int

	leakThreshold time.Duration

	allocCount uint64 // atomic; allocations since the last publish (rate)

	mu       sync.Mutex
	siteAddr map[int32]uint64 // stack_id → resolved app call-site (cache)
	lastAt   time.Time        // publishLoop-only; rate baseline
}

const (
	heapDefaultLeakThreshold = 10 * time.Second
	heapTopCallSites         = 8
	heapPublishInterval      = 500 * time.Millisecond
)

func NewHeapEBPFCollector() *HeapEBPFCollector {
	return &HeapEBPFCollector{
		ch:            make(chan interface{}, 64),
		stop:          make(chan struct{}),
		leakThreshold: heapDefaultLeakThreshold,
		siteAddr:      make(map[int32]uint64),
	}
}

func (c *HeapEBPFCollector) Start(pid int) error {
	tracer, err := bpf.OpenHeapTracer(pid)
	if err != nil {
		return fmt.Errorf("heap eBPF: %w", err)
	}
	c.tracer = tracer
	c.pid = pid
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
}

func (c *HeapEBPFCollector) Subscribe() <-chan interface{} { return c.ch }

func (c *HeapEBPFCollector) readLoop() {
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
		}
		he := HeapEvent{
			Op:         heapOpName(ev.Op),
			Size:       ev.Size,
			Addr:       ev.Addr,
			LifetimeMs: float64(ev.LifetimeNs) / 1e6,
			CallSite:   c.resolveSite(ev.StackID),
			Large:      ev.Flags&bpf.HeapFlagLarge != 0,
		}
		select {
		case c.ch <- he:
		default:
		}
	}
}

// resolveSite maps a stack_id to the application call-site address, caching it
// (stacks are stable for the process lifetime).
func (c *HeapEBPFCollector) resolveSite(stackID int32) uint64 {
	if stackID < 0 {
		return 0
	}
	c.mu.Lock()
	if a, ok := c.siteAddr[stackID]; ok {
		c.mu.Unlock()
		return a
	}
	c.mu.Unlock()

	frames, err := c.tracer.ResolveStack(stackID)
	if err != nil {
		return 0
	}
	lo, hi := c.tracer.LibcRange()
	addr := pickAppFrame(frames, lo, hi)

	c.mu.Lock()
	c.siteAddr[stackID] = addr
	c.mu.Unlock()
	return addr
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
		addr := c.resolveSite(sid)
		sites = append(sites, HeapCallSite{
			CallSite:      addr,
			AddrHex:       heapAddrHex(addr),
			LiveBytes:     uint64(lb),
			AllocCount:    raw.AllocCount,
			AvgLifetimeMs: avgLifeMs,
			Suspected:     leakBytes[sid] > 0,
		})
	}

	now := time.Now()
	var rate float64
	if !c.lastAt.IsZero() {
		if elapsed := now.Sub(c.lastAt).Seconds(); elapsed > 0 {
			rate = float64(atomic.SwapUint64(&c.allocCount, 0)) / elapsed
		}
	} else {
		atomic.StoreUint64(&c.allocCount, 0) // discard the warm-up interval
	}
	c.lastAt = now

	return HeapStats{
		Timestamp:          now,
		LiveHeapBytes:      liveTotal,
		AllocRate:          rate,
		TopCallSites:       chooseTopCallSites(sites, heapTopCallSites),
		SuspectedLeakBytes: suspectedTotal,
	}, nil
}
