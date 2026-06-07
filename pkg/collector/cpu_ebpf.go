//go:build linux && ebpf

package collector

import (
	"fmt"
	"sync"
	"time"

	"github.com/trentas/ptop/internal/bpf"
)

// CPUEBPFCollector consumes the on-CPU sample counter from the perf_event
// tracer (internal/bpf/cpu.go) and publishes CpuSample{UsagePct} every 1s.
//
// Calculation:
//   delta_samples / (SampleFreq × NCPU × elapsed_seconds) × 100 × NCPU
//   = delta_samples / (SampleFreq × elapsed_seconds) × 100
//   = single-core % (top-style; can exceed 100% when multi-threaded)
//
// In builds without -tags=ebpf or non-Linux OS, the parallel stub always
// fails in Start, leading the model to use the /proc collector or simulation.
type CPUEBPFCollector struct {
	tracer *bpf.CPUTracer
	ch     chan interface{}
	stop   chan struct{}

	mu       sync.Mutex
	lastSamp uint64
	lastAt   time.Time
}

func NewCPUEBPFCollector() *CPUEBPFCollector {
	return &CPUEBPFCollector{
		ch:   make(chan interface{}, 16),
		stop: make(chan struct{}),
	}
}

func (c *CPUEBPFCollector) Start(pid int) error {
	tracer, err := bpf.OpenCPUTracer(pid)
	if err != nil {
		return fmt.Errorf("cpu eBPF: %w", err)
	}
	c.tracer = tracer
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
	count, err := c.tracer.SampleCount()
	if err != nil {
		return CpuSample{}, err
	}

	now := time.Now()
	var pct float64
	if !c.lastAt.IsZero() {
		elapsed := now.Sub(c.lastAt).Seconds()
		if elapsed > 0 && count >= c.lastSamp {
			delta := float64(count - c.lastSamp)
			// pct = single-core %. SampleFreq samples per second per CPU
			// give NCPU × SampleFreq samples/s in total. delta in that
			// interval represents fractions of CPU used by the target.
			//
			// pct = (delta / (SampleFreq × elapsed)) × 100
			pct = (delta / (float64(bpf.SampleFreq) * elapsed)) * 100
			if pct > float64(c.tracer.NumCPU()*100) {
				pct = float64(c.tracer.NumCPU() * 100) // saturation
			}
		}
	}
	c.lastSamp = count
	c.lastAt = now

	return CpuSample{
		UsagePct:  pct,
		Timestamp: now,
	}, nil
}
