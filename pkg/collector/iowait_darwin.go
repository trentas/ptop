//go:build darwin

package collector

import (
	"fmt"
	"sync"
	"time"
)

// IOWaitCollector approximates per-process I/O-wait % from the fraction of
// the process's threads sitting in the uninterruptible-blocked state.
//
// macOS doesn't expose a `delayacct_blkio_ticks` equivalent in libproc, but
// we can infer "thread is blocked on synchronous disk I/O" from
// ProcPidThreadInfo.RunState == ThreadStateUninterruptible. That maps to
// Linux 'D' state — the canonical signal for "waiting on disk".
//
// Each snapshot records blocked/total threads; the published % is that ratio
// averaged over the publish window. Averaging the *fraction* (rather than
// counting snapshots where any thread was blocked) avoids the multi-thread
// bias where a single stuck thread in a 100-thread process would read as
// 100% iowait.
//
// Caveats:
//   - Imprecise: thread state is sampled every 100ms, so we get the fraction
//     of threads in 'D' at sample points, not the actual fraction of time.
//     A thread that blocks for <100ms between samples is invisible.
//   - For a coarse "how disk-bound is this process right now?" indicator it's
//     useful; for accurate iowait accounting we'd need eBPF-grade tracing
//     and macOS doesn't have the Tier 1 path for that.

type IOWaitCollector struct {
	pid  int
	ch   chan interface{}
	stop chan struct{}
	mu   sync.Mutex

	samples     int     // total state snapshots taken since last publish
	blockedFrac float64 // running sum of (blocked threads / total threads) per snapshot
}

func NewIOWaitCollector() *IOWaitCollector {
	return &IOWaitCollector{
		ch:   make(chan interface{}, 16),
		stop: make(chan struct{}),
	}
}

func (c *IOWaitCollector) Start(pid int) error {
	c.pid = pid
	if _, err := ListThreads(pid); err != nil {
		return fmt.Errorf("IO wait collector unavailable for pid %d: %w", pid, err)
	}
	go c.loop()
	return nil
}

func (c *IOWaitCollector) Stop()                          { close(c.stop) }
func (c *IOWaitCollector) Subscribe() <-chan interface{}  { return c.ch }

func (c *IOWaitCollector) loop() {
	// Sample thread states 10× per second; publish the rolling % every 500ms.
	sampleT := time.NewTicker(100 * time.Millisecond)
	publishT := time.NewTicker(500 * time.Millisecond)
	defer sampleT.Stop()
	defer publishT.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-sampleT.C:
			c.snapshot()
		case <-publishT.C:
			c.publish()
		}
	}
}

func (c *IOWaitCollector) snapshot() {
	tids, err := ListThreads(c.pid)
	if err != nil {
		return
	}
	total := 0
	blocked := 0
	for _, tid := range tids {
		info, err := ProcPidThreadInfo(c.pid, tid)
		if err != nil {
			continue // thread may have exited between list and per-thread call
		}
		total++
		if info.RunState == ThreadStateUninterruptible {
			blocked++
		}
	}
	if total == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.samples++
	c.blockedFrac += float64(blocked) / float64(total)
}

func (c *IOWaitCollector) publish() {
	c.mu.Lock()
	now := time.Now()
	var pct float64
	if c.samples > 0 {
		pct = c.blockedFrac / float64(c.samples) * 100
	}
	c.samples = 0
	c.blockedFrac = 0
	c.mu.Unlock()

	select {
	case c.ch <- IOWaitSample{Pct: pct, Timestamp: now}:
	default:
	}
}
