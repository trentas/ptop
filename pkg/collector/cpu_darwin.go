//go:build darwin

package collector

import (
	"fmt"
	"sync"
	"time"
)

// CPUCollector samples per-process CPU% on macOS via proc_pidinfo(PROC_PIDTASKINFO).
//
// ProcPidTaskInfo returns user/system time in NANOSECONDS (after timebase
// conversion from mach absolute time inside libproc_darwin.go). The math
// here is then trivial: pct = ΔnsCPU / Δnsreal × 100 (single-core %; values
// can exceed 100 for multi-threaded workloads using multiple cores).
//
// Owned-process constraint: proc_pidinfo only works for processes of the
// same euid (or root). Start fails with EPERM otherwise — the model falls
// back to simulated data, same as on Linux without /proc access.

type CPUCollector struct {
	pid  int
	ch   chan interface{}
	stop chan struct{}
	mu   sync.Mutex

	lastTotalNs  uint64
	lastSampleAt time.Time
}

func NewCPUCollector() *CPUCollector {
	return &CPUCollector{
		ch:   make(chan interface{}, 16),
		stop: make(chan struct{}),
	}
}

func (c *CPUCollector) Start(pid int) error {
	c.pid = pid
	// Sanity probe: a successful first call confirms (a) the pid exists and
	// (b) the current euid is allowed to query it.
	if _, err := ProcPidTaskInfo(pid); err != nil {
		return fmt.Errorf("CPU collector unavailable for pid %d: %w", pid, err)
	}
	go c.loop()
	return nil
}

func (c *CPUCollector) Stop()                          { close(c.stop) }
func (c *CPUCollector) Subscribe() <-chan interface{}  { return c.ch }

func (c *CPUCollector) loop() {
	t := time.NewTicker(500 * time.Millisecond)
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

func (c *CPUCollector) sample() (CpuSample, error) {
	info, err := ProcPidTaskInfo(c.pid)
	if err != nil {
		return CpuSample{}, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	totalNs := info.UserTimeNs + info.SystemTimeNs

	var pct float64
	if !c.lastSampleAt.IsZero() {
		elapsedNs := uint64(now.Sub(c.lastSampleAt).Nanoseconds())
		if elapsedNs > 0 && totalNs >= c.lastTotalNs {
			deltaNs := totalNs - c.lastTotalNs
			pct = float64(deltaNs) / float64(elapsedNs) * 100
		}
	}
	c.lastTotalNs = totalNs
	c.lastSampleAt = now

	return CpuSample{
		UsagePct:  pct,
		Timestamp: now,
	}, nil
}
