//go:build linux && ebpf

package collector

import (
	"fmt"
	"sync"
	"time"

	"github.com/trentas/ptop/internal/bpf"
)

// CPUEBPFCollector turns the on-CPU nanosecond counter kept by the scheduler
// tracer (internal/bpf/cpu.go) into a CpuSample{UsagePct} every second:
//
//	pct = Δ on-CPU ns / Δ wall ns × 100
//
// That is single-core % (top-style; a multi-threaded target can exceed 100%)
// and it is the same quantity /proc reports as utime+stime, measured in
// nanoseconds rather than 10ms ticks. Before #108 this divided a count of
// 100Hz perf samples by an assumed sampling rate, which agreed with /proc only
// on average and, over the one-second buckets this publishes, mostly did not:
// see programs/cpu.bpf.c.
//
// In builds without -tags=ebpf or non-Linux OS, the parallel stub always
// fails in Start, leading the model to use the /proc collector or simulation.
type CPUEBPFCollector struct {
	tracer *bpf.CPUTracer
	ch     chan interface{}
	stop   chan struct{}

	mu     sync.Mutex
	lastNs uint64
	lastAt time.Time
}

func NewCPUEBPFCollector() *CPUEBPFCollector {
	return &CPUEBPFCollector{
		ch:   make(chan interface{}, 16),
		stop: make(chan struct{}),
	}
}

func (c *CPUEBPFCollector) Start(pid int) error { return c.start(bpf.TargetPID(pid)) }

// StartCgroup samples every process in a cgroup subtree instead of one pid
// (#94). Implements CgroupTargeter.
func (c *CPUEBPFCollector) StartCgroup(spec string) error { return c.start(bpf.TargetCgroup(spec)) }

func (c *CPUEBPFCollector) start(t bpf.Target) error {
	tracer, err := bpf.OpenCPUTracer(t)
	if err != nil {
		return fmt.Errorf("cpu eBPF: %w", err)
	}
	c.tracer = tracer
	// Take the baseline now rather than on the first tick: with no baseline
	// the first published sample is a structural zero, and a zero on this
	// axis reads as an idle process rather than as "not measured yet".
	if ns, err := tracer.OnCPUNanos(); err == nil {
		c.lastNs, c.lastAt = ns, time.Now()
	}
	go c.loop()
	return nil
}

func (c *CPUEBPFCollector) Stop() {
	close(c.stop)
	if c.tracer != nil {
		_ = c.tracer.Close()
		c.tracer = nil
	}
}

func (c *CPUEBPFCollector) Subscribe() <-chan interface{} {
	return c.ch
}

func (c *CPUEBPFCollector) loop() {
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

func (c *CPUEBPFCollector) sample() (CpuSample, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.tracer == nil {
		return CpuSample{}, fmt.Errorf("tracer not open")
	}
	ns, err := c.tracer.OnCPUNanos()
	if err != nil {
		return CpuSample{}, err
	}

	now := time.Now()
	var pct float64
	if !c.lastAt.IsZero() {
		pct = cpuPercent(c.lastNs, ns, now.Sub(c.lastAt), c.tracer.NumCPU())
	}
	c.lastNs = ns
	c.lastAt = now

	return CpuSample{
		UsagePct:  pct,
		Timestamp: now,
	}, nil
}
