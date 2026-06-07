//go:build linux

package collector

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// IOWaitCollector reads /proc/<pid>/stat field 42 (delayacct_blkio_ticks)
// and converts it into the % of wallclock the process spent blocked on
// synchronous block I/O during the last interval.
//
// This is the canonical source for "is this process waiting on disk?" — the
// global `iowait` from top/vmstat is a system-wide stat for idle CPU time,
// NOT attributable to a PID. delayacct_blkio_ticks is per-task and exact.
//
// Requires kernel with CONFIG_TASK_DELAY_ACCT (default in modern distros).
// On 5.14+ kernels may require boot param `delayacct=on`. When the kernel
// doesn't export the field, parseProcStatTimes returns blkio=0 with no
// error — the collector keeps publishing 0%, signaling "no data".
type IOWaitCollector struct {
	pid  int
	ch   chan interface{}
	stop chan struct{}
	mu   sync.Mutex

	lastBlkio uint64
	lastAt    time.Time
}

func NewIOWaitCollector() *IOWaitCollector {
	return &IOWaitCollector{
		ch:   make(chan interface{}, 16),
		stop: make(chan struct{}),
	}
}

func (c *IOWaitCollector) Start(pid int) error {
	c.pid = pid
	if _, err := os.Stat(fmt.Sprintf("/proc/%d/stat", pid)); err != nil {
		return fmt.Errorf("process %d not found: %w", pid, err)
	}
	go c.loop()
	return nil
}

func (c *IOWaitCollector) Stop()                          { close(c.stop) }
func (c *IOWaitCollector) Subscribe() <-chan interface{}  { return c.ch }

func (c *IOWaitCollector) loop() {
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

func (c *IOWaitCollector) sample() (IOWaitSample, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", c.pid))
	if err != nil {
		return IOWaitSample{}, err
	}
	_, _, _, _, blkio, err := parseProcStatTimes(data)
	if err != nil {
		return IOWaitSample{}, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var pct float64
	if !c.lastAt.IsZero() {
		elapsed := now.Sub(c.lastAt).Seconds()
		if elapsed > 0 && blkio >= c.lastBlkio {
			deltaTicks := float64(blkio - c.lastBlkio)
			// % of wallclock: deltaTicks/clkTck = seconds waiting on I/O.
			// Divided by elapsed = fraction; ×100 = %.
			pct = (deltaTicks / clkTck) / elapsed * 100
			if pct > 100 {
				pct = 100 // multi-thread saturation in rare cases
			}
		}
	}
	c.lastBlkio = blkio
	c.lastAt = now

	return IOWaitSample{
		Pct:       pct,
		Timestamp: now,
	}, nil
}
