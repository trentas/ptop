//go:build darwin

package collector

import (
	"fmt"
	"sync"
	"time"
)

// ThreadsCollector lists threads via ListThreads + ProcPidThreadInfo and
// publishes a []ThreadInfo snapshot every 1 second.
//
// Differences vs Linux /proc/<pid>/task:
//   - TID is a Mach thread port ID (uint64), not a Linux kernel TID. Values
//     are large (8-billion range typical) and stable for the thread's life,
//     but not human-friendly. The F4 view renders them as-is for now.
//   - Waiting ("wchan") stays empty: libproc has no equivalent to
//     /proc/<tid>/wchan. The eBPF-only Linux build is what gives the
//     real-time "blocked on futex X" info; on darwin Tier 1 that's lost.
//   - CtxSwitches stays 0 (eBPF sched_switch only).

type ThreadsCollector struct {
	pid  int
	ch   chan interface{}
	stop chan struct{}
	mu   sync.Mutex

	prev         map[uint64]uint64 // mach tid → total ns (user+system)
	lastSampleAt time.Time
}

func NewThreadsCollector() *ThreadsCollector {
	return &ThreadsCollector{
		ch:   make(chan interface{}, 16),
		stop: make(chan struct{}),
		prev: make(map[uint64]uint64),
	}
}

func (c *ThreadsCollector) Start(pid int) error {
	c.pid = pid
	if _, err := ListThreads(pid); err != nil {
		return fmt.Errorf("Threads collector unavailable for pid %d: %w", pid, err)
	}
	go c.loop()
	return nil
}

func (c *ThreadsCollector) Stop()                          { close(c.stop) }
func (c *ThreadsCollector) Subscribe() <-chan interface{}  { return c.ch }

func (c *ThreadsCollector) loop() {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			if threads, err := c.collect(); err == nil {
				select {
				case c.ch <- threads:
				default:
				}
			}
		}
	}
}

func (c *ThreadsCollector) collect() ([]ThreadInfo, error) {
	tids, err := ListThreads(c.pid)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	elapsed := 0.0
	if !c.lastSampleAt.IsZero() {
		elapsed = now.Sub(c.lastSampleAt).Seconds()
	}

	seen := make(map[uint64]bool, len(tids))
	out := make([]ThreadInfo, 0, len(tids))
	for _, tid := range tids {
		seen[tid] = true
		info, err := ProcPidThreadInfo(c.pid, tid)
		if err != nil {
			continue // thread may have exited between ListThreads and the per-thread call
		}
		totalNs := info.UserTimeNs + info.SystemTimeNs

		var cpuPct float64
		if prev, hadPrev := c.prev[tid]; hadPrev && elapsed > 0 && totalNs >= prev {
			cpuPct = float64(totalNs-prev) / (elapsed * 1e9) * 100
		}
		c.prev[tid] = totalNs

		out = append(out, ThreadInfo{
			TID:     int(tid),
			Name:    info.Name,
			State:   threadRunStateLabel(info.RunState),
			CPUPct:  cpuPct,
			Waiting: "", // not exposed by libproc; see file header
		})
	}

	for tid := range c.prev {
		if !seen[tid] {
			delete(c.prev, tid)
		}
	}

	c.lastSampleAt = now
	return out, nil
}

// threadRunStateLabel maps Mach TH_STATE_* values to the same string labels
// the Linux collector uses, so the F4 view's state coloring works unchanged.
func threadRunStateLabel(rs int32) string {
	switch rs {
	case ThreadStateRunning:
		return "running"
	case ThreadStateWaiting:
		return "sleeping"
	case ThreadStateUninterruptible:
		return "blocked"
	case ThreadStateStopped, ThreadStateHalted:
		return "stopped"
	default:
		return "unknown"
	}
}
