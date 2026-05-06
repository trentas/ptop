//go:build linux && ebpf

package collector

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trentas/ptop/internal/bpf"
)

// MemEBPFCollector is a hybrid /proc + eBPF collector:
//
//   - /proc/<pid>/statm  → RSS, approximate heap (data segment, includes heap+anon)
//   - eBPF mem_counters  → page_faults, mmap+brk count
//
// Replaces the "allocs/s = delta(page_faults)" proxy of the /proc-only
// MemCollector with a real count of mmap+brk syscalls — a metric that
// reflects actual userspace allocations, not TLB faults.
type MemEBPFCollector struct {
	tracer *bpf.MemoryTracer
	pid    int
	ch     chan interface{}
	stop   chan struct{}

	mu          sync.Mutex
	prev        bpf.MemCounters
	lastSampleAt time.Time
}

func NewMemEBPFCollector() *MemEBPFCollector {
	return &MemEBPFCollector{
		ch:   make(chan interface{}, 4),
		stop: make(chan struct{}),
	}
}

func (c *MemEBPFCollector) Start(pid int) error {
	if _, err := os.Stat(fmt.Sprintf("/proc/%d/statm", pid)); err != nil {
		return fmt.Errorf("process %d not found: %w", pid, err)
	}
	tracer, err := bpf.OpenMemoryTracer(pid)
	if err != nil {
		return fmt.Errorf("memory eBPF: %w", err)
	}
	c.tracer = tracer
	c.pid = pid
	go c.loop()
	return nil
}

func (c *MemEBPFCollector) Stop() {
	close(c.stop)
	if c.tracer != nil {
		_ = c.tracer.Close()
		c.tracer = nil
	}
}

func (c *MemEBPFCollector) Subscribe() <-chan interface{} {
	return c.ch
}

func (c *MemEBPFCollector) loop() {
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

func (c *MemEBPFCollector) sample() (MemStats, error) {
	// /proc/<pid>/statm: size resident shared text lib data dirty (in pages)
	statmData, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", c.pid))
	if err != nil {
		return MemStats{}, err
	}
	fields := strings.Fields(string(statmData))
	if len(fields) < 7 {
		return MemStats{}, fmt.Errorf("malformed /proc/.../statm: %d fields", len(fields))
	}
	pageSize := uint64(os.Getpagesize())
	resident, _ := strconv.ParseUint(fields[1], 10, 64)
	dataPages, _ := strconv.ParseUint(fields[5], 10, 64)

	// eBPF counters
	cnt, err := c.tracer.Stats()
	if err != nil {
		return MemStats{}, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var allocsPerS uint64
	if !c.lastSampleAt.IsZero() {
		elapsed := now.Sub(c.lastSampleAt).Seconds()
		if elapsed > 0 {
			deltaAlloc := (cnt.MmapCount - c.prev.MmapCount) +
				(cnt.BrkCount - c.prev.BrkCount)
			allocsPerS = uint64(float64(deltaAlloc) / elapsed)
		}
	}
	c.prev = cnt
	c.lastSampleAt = now

	return MemStats{
		RSSBytes:   resident * pageSize,
		HeapBytes:  dataPages * pageSize, // approximation: data segment ~ heap+anon
		PageFaults: cnt.PageFaults,
		AllocsPerS: allocsPerS,
	}, nil
}
