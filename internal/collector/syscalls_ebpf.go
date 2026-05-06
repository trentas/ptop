//go:build linux && ebpf

package collector

import (
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/trentas/xray/internal/bpf"
)

// SyscallsEBPFCollector consumes the syscall_count map from the eBPF
// syscalls program (internal/bpf/syscalls.go) and publishes a
// map[name]Stat snapshot every 500ms to the Model.
//
// Runs only on Linux with -tags=ebpf. In other builds, the non-Linux Stub
// returns nil from New and Start always fails.
type SyscallsEBPFCollector struct {
	tracer *bpf.SyscallTracer
	ch     chan interface{}
	stop   chan struct{}

	mu      sync.Mutex
	isARM64 bool
}

func NewSyscallsEBPFCollector() *SyscallsEBPFCollector {
	return &SyscallsEBPFCollector{
		ch:      make(chan interface{}, 16),
		stop:    make(chan struct{}),
		isARM64: runtime.GOARCH == "arm64",
	}
}

func (c *SyscallsEBPFCollector) Start(pid int) error {
	tracer, err := bpf.OpenSyscallTracer(pid)
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
				select {
				case c.ch <- snap:
				default:
				}
			}
		}
	}
}

// snapshot reads the syscall_count map and returns {name → count}.
// Latency is available but not exported for now — the Model only consumes
// counts today. When F2 grows a LAT/MED column, we revisit this.
func (c *SyscallsEBPFCollector) snapshot() (map[string]uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tracer == nil {
		return nil, fmt.Errorf("tracer not open")
	}
	stats, err := c.tracer.Stats()
	if err != nil {
		return nil, err
	}
	out := make(map[string]uint64, len(stats))
	for id, st := range stats {
		out[syscallName(id, c.isARM64)] = st.Count
	}
	return out, nil
}
