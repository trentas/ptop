//go:build darwin

package collector

import (
	"fmt"
	"sync"
	"time"
)

// MemCollector samples per-process memory stats on macOS via libproc.
//
// Fields mapping (vs the Linux /proc collector):
//   - RSSBytes:   ProcPidTaskInfo.ResidentSize — direct equivalent.
//   - HeapBytes:  unavailable without task_for_pid() (restricted on macOS).
//                 VirtualSize is the only public scalar but on Go programs
//                 it's ~hundreds of GB due to Go's arena reservation; would
//                 mislead more than inform. Left as 0.
//   - PageFaults: ProcPidTaskInfo.FaultCount — cumulative since process start.
//   - AllocsPerS: page-fault growth rate (same proxy the Linux collector uses).

type MemCollector struct {
	pid  int
	ch   chan interface{}
	stop chan struct{}
	mu   sync.Mutex

	lastFaults uint64
	lastAt     time.Time
}

func NewMemCollector() *MemCollector {
	return &MemCollector{
		ch:   make(chan interface{}, 16),
		stop: make(chan struct{}),
	}
}

func (c *MemCollector) Start(pid int) error {
	c.pid = pid
	if _, err := ProcPidTaskInfo(pid); err != nil {
		return fmt.Errorf("Memory collector unavailable for pid %d: %w", pid, err)
	}
	go c.loop()
	return nil
}

func (c *MemCollector) Stop()                          { close(c.stop) }
func (c *MemCollector) Subscribe() <-chan interface{}  { return c.ch }

func (c *MemCollector) loop() {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			if s, err := c.sample(); err == nil {
				select {
				case c.ch <- s:
				default:
				}
			}
		}
	}
}

func (c *MemCollector) sample() (MemStats, error) {
	info, err := ProcPidTaskInfo(c.pid)
	if err != nil {
		return MemStats{}, err
	}
	totalFaults := uint64(info.FaultCount)

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var allocsPerS uint64
	if !c.lastAt.IsZero() {
		elapsed := now.Sub(c.lastAt).Seconds()
		if elapsed > 0 && totalFaults >= c.lastFaults {
			allocsPerS = uint64(float64(totalFaults-c.lastFaults) / elapsed)
		}
	}
	c.lastFaults = totalFaults
	c.lastAt = now

	return MemStats{
		RSSBytes:   info.ResidentSize,
		HeapBytes:  0,
		PageFaults: totalFaults,
		AllocsPerS: allocsPerS,
	}, nil
}
