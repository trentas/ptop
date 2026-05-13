//go:build darwin

package collector

import (
	"fmt"
	"sync"
	"time"
)

// IOWaitCollector approximates per-process I/O-wait % by summing the
// blocked-uninterruptible time across the process's threads.
//
// macOS doesn't expose a `delayacct_blkio_ticks` equivalent in libproc, but
// we can infer "thread is blocked on synchronous disk I/O" from
// ProcPidThreadInfo.RunState == ThreadStateUninterruptible. That maps to
// Linux 'D' state — the canonical signal for "waiting on disk".
//
// Caveats:
//   - Imprecise: thread state is sampled instantaneously every 500ms; we
//     get the fraction of samples in 'D', not the actual fraction of time.
//     A thread that blocks for 100ms between samples is invisible.
//   - For a coarse "is this process disk-bound right now?" indicator it's
//     useful; for accurate iowait accounting we'd need eBPF-grade tracing
//     and macOS doesn't have the Tier 1 path for that.

type IOWaitCollector struct {
	pid  int
	ch   chan interface{}
	stop chan struct{}
	mu   sync.Mutex

	samples       int // total state snapshots taken since last publish
	blockedHits   int // snapshots where at least one thread was in 'D'
	lastPublishAt time.Time
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
	c.lastPublishAt = time.Now()
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
	anyBlocked := false
	for _, tid := range tids {
		info, err := ProcPidThreadInfo(c.pid, tid)
		if err != nil {
			continue
		}
		if info.RunState == ThreadStateUninterruptible {
			anyBlocked = true
			break
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.samples++
	if anyBlocked {
		c.blockedHits++
	}
}

func (c *IOWaitCollector) publish() {
	c.mu.Lock()
	now := time.Now()
	var pct float64
	if c.samples > 0 {
		pct = float64(c.blockedHits) / float64(c.samples) * 100
	}
	c.samples = 0
	c.blockedHits = 0
	c.lastPublishAt = now
	c.mu.Unlock()

	select {
	case c.ch <- IOWaitSample{Pct: pct, Timestamp: now}:
	default:
	}
}
