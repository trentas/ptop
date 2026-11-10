//go:build linux && ebpf

package collector

import (
	"sort"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/trentas/ptop/internal/bpf"
)

// SyscallsEBPFCollector consumes the syscall_count map from the eBPF
// syscalls program (internal/bpf/syscalls.go) and publishes a []SyscallEvent
// snapshot — count and summed latency per syscall — every 500ms.
//
// Runs only on Linux with -tags=ebpf. In other builds, the non-Linux Stub
// returns nil from New and Start always fails.
type SyscallsEBPFCollector struct {
	tracer *bpf.SyscallTracer
	ch     chan interface{}
	stop   chan struct{}

	mu    sync.Mutex
	names []string // syscall number → name, for the architecture this binary runs on
}

func NewSyscallsEBPFCollector() *SyscallsEBPFCollector {
	return &SyscallsEBPFCollector{
		ch:    make(chan interface{}, 16),
		stop:  make(chan struct{}),
		names: syscallTable(runtime.GOARCH),
	}
}

func (c *SyscallsEBPFCollector) Start(pid int) error { return c.start(bpf.TargetPID(pid)) }

// StartCgroup counts syscalls across a whole cgroup subtree instead of one pid
// (#94). Implements CgroupTargeter.
func (c *SyscallsEBPFCollector) StartCgroup(spec string) error {
	return c.start(bpf.TargetCgroup(spec))
}

func (c *SyscallsEBPFCollector) start(t bpf.Target) error {
	tracer, err := bpf.OpenSyscallTracer(t)
	if err != nil {
		return fmt.Errorf("syscalls eBPF: %w", err)
	}
	c.tracer = tracer
	go c.loop()
	return nil
}

func (c *SyscallsEBPFCollector) Stop() {
	close(c.stop)
	if c.tracer != nil {
		_ = c.tracer.Close()
		c.tracer = nil
	}
}

func (c *SyscallsEBPFCollector) Subscribe() <-chan interface{} {
	return c.ch
}

func (c *SyscallsEBPFCollector) loop() {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			if snap, err := c.snapshot(); err == nil {
				publish(c.ch, snap)
			}
		}
	}
}

// snapshot reads the syscall_count map and returns one row per syscall,
// busiest first. The kernel bumps both counters at the same exit, since attach,
// so each row's LatencyNs covers exactly its Count calls (#139).
func (c *SyscallsEBPFCollector) snapshot() ([]SyscallEvent, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tracer == nil {
		return nil, fmt.Errorf("tracer not open")
	}
	stats, err := c.tracer.Stats()
	if err != nil {
		return nil, err
	}
	classes, _ := c.tracer.FdClassStats() // nil from an object without the map: no split, as before
	out := make([]SyscallEvent, 0, len(stats))
	for id, st := range stats {
		ev := SyscallEvent{
			Name:      syscallName(id, c.names),
			Count:     st.Count,
			LatencyNs: st.TotalLatNs,
		}
		for name, cs := range classes[id] {
			ev.FdClasses = append(ev.FdClasses, FdClassStat{Class: name, Count: cs.Count, LatencyNs: cs.TotalLatNs})
		}
		sort.Slice(ev.FdClasses, func(i, j int) bool { return ev.FdClasses[i].Class < ev.FdClasses[j].Class })
		out = append(out, ev)
	}
	sortSyscallRows(out)
	return out, nil
}
