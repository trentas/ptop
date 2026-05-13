//go:build darwin

package collector

import (
	"fmt"
	"sync"
	"time"
)

// IOThroughputCollector samples cumulative disk I/O bytes via
// proc_pid_rusage(RUSAGE_INFO_V4) every 500ms, deriving per-second
// throughput from deltas.
//
// Notes vs the Linux /proc collector:
//   - ReadOps / WriteOps stay at 0: libproc has no per-process syscall
//     counters equivalent to /proc/<pid>/io's syscr/syscw. The F5 view's
//     "Reads/s" column will display 0 on darwin.
//   - These byte counters cover storage-level I/O only (cache hits don't
//     count) — same semantics as Linux read_bytes/write_bytes, so the
//     UI's "iotop-like" framing is consistent across OSes.

type IOThroughputCollector struct {
	pid  int
	ch   chan interface{}
	stop chan struct{}
	mu   sync.Mutex

	lastReadBytes  uint64
	lastWriteBytes uint64
	lastAt         time.Time
}

func NewIOThroughputCollector() *IOThroughputCollector {
	return &IOThroughputCollector{
		ch:   make(chan interface{}, 16),
		stop: make(chan struct{}),
	}
}

func (c *IOThroughputCollector) Start(pid int) error {
	c.pid = pid
	if _, err := ProcPidRUsage(pid); err != nil {
		return fmt.Errorf("IO throughput collector unavailable for pid %d: %w", pid, err)
	}
	go c.loop()
	return nil
}

func (c *IOThroughputCollector) Stop()                          { close(c.stop) }
func (c *IOThroughputCollector) Subscribe() <-chan interface{}  { return c.ch }

func (c *IOThroughputCollector) loop() {
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

func (c *IOThroughputCollector) sample() (IOThroughputSample, error) {
	r, err := ProcPidRUsage(c.pid)
	if err != nil {
		return IOThroughputSample{}, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var rps, wps float64
	if !c.lastAt.IsZero() {
		elapsed := now.Sub(c.lastAt).Seconds()
		if elapsed > 0 {
			if r.DiskIOBytesRead >= c.lastReadBytes {
				rps = float64(r.DiskIOBytesRead-c.lastReadBytes) / elapsed
			}
			if r.DiskIOBytesWrite >= c.lastWriteBytes {
				wps = float64(r.DiskIOBytesWrite-c.lastWriteBytes) / elapsed
			}
		}
	}
	c.lastReadBytes = r.DiskIOBytesRead
	c.lastWriteBytes = r.DiskIOBytesWrite
	c.lastAt = now

	return IOThroughputSample{
		ReadBytesPerS:  rps,
		WriteBytesPerS: wps,
		ReadOps:        0,
		WriteOps:       0,
		Timestamp:      now,
	}, nil
}
