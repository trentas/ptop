//go:build linux && ebpf

package collector

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/trentas/ptop/internal/bpf"
)

// FutexEBPFCollector consumes the futex_stats map periodically and publishes
// a []LockEntry ranked by contention in the current window (delta of
// waits in the last interval). Emits TimelineEvent category="lock" when
// some uaddr passes the contention threshold for the interval.
type FutexEBPFCollector struct {
	tracer *bpf.FutexTracer
	ch     chan interface{}
	stop   chan struct{}

	mu   sync.Mutex
	prev map[uint64]bpf.FutexStat
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
		ch:   make(chan interface{}, 8),
		stop: make(chan struct{}),
		prev: make(map[uint64]bpf.FutexStat),
	}
}

func (c *FutexEBPFCollector) Start(pid int) error {
	tracer, err := bpf.OpenFutexTracer(pid)
	if err != nil {
		return fmt.Errorf("futex eBPF: %w", err)
	}
	c.tracer = tracer
	go c.loop()
	return nil
}

func (c *FutexEBPFCollector) Stop() {
	close(c.stop)
	if c.tracer != nil {
		_ = c.tracer.Close()
		c.tracer = nil
	}
}

func (c *FutexEBPFCollector) Subscribe() <-chan interface{} {
	return c.ch
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
			// Timeline events: one per "hot" uaddr in the interval.
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
						"futex@0x%x ↑ %d waits (avg %.1fms, last tid %d)",
						e.UAddr, e.WaitDelta, e.LatencyMs, e.LastWaitTID,
					),
				}:
					emitted++
				default:
				}
			}
		}
	}
}

// snapshot reads futex_stats, computes delta vs prev, returns the top-N
// by window contention and the "hot" list (those past the threshold for
// emitting timeline events).
func (c *FutexEBPFCollector) snapshot() (snap []LockEntry, hot []LockEntry) {
	if c.tracer == nil {
		return nil, nil
	}
	stats, err := c.tracer.Stats()
	if err != nil {
		return nil, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	all := make([]LockEntry, 0, len(stats))
	for uaddr, s := range stats {
		p := c.prev[uaddr]
		waitDelta := s.WaitCount - p.WaitCount
		latMs := 0.0
		if s.LatCount > 0 {
			latMs = float64(s.LatSumNs) / float64(s.LatCount) / 1e6
		}
		entry := LockEntry{
			UAddr:       uaddr,
			Waiters:     s.WaitCount,
			Wakers:      s.WakeCount,
			WaitDelta:   waitDelta,
			LatencyMs:   latMs,
			LastWaitTID: int(s.LastWaitTID),
			LastWakeTID: int(s.LastWakeTID),
		}
		all = append(all, entry)
		if waitDelta >= contentionThreshold {
			hot = append(hot, entry)
		}
	}
	c.prev = stats

	// Ranking: by WaitDelta desc, with total Waiters as tiebreaker.
	sort.Slice(all, func(i, j int) bool {
		if all[i].WaitDelta != all[j].WaitDelta {
			return all[i].WaitDelta > all[j].WaitDelta
		}
		return all[i].Waiters > all[j].Waiters
	})
	if len(all) > topLockEntries {
		all = all[:topLockEntries]
	}
	// Hot list also sorted by delta desc.
	sort.Slice(hot, func(i, j int) bool {
		return hot[i].WaitDelta > hot[j].WaitDelta
	})
	return all, hot
}
