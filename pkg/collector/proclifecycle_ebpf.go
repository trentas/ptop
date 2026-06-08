//go:build linux && ebpf

package collector

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/trentas/ptop/internal/bpf"
)

// ProcLifecycleEBPFCollector consumes the sched fork/exec/exit ring buffer of
// the eBPF proc tracer and publishes one ProcLifecycleEvent per event in the
// target's descendant subtree (#60). There is no /proc fallback and no
// simulation — lineage is surfaced only when eBPF can attach the tracepoints.
type ProcLifecycleEBPFCollector struct {
	tracer *bpf.ProcTracer
	ch     chan interface{}
	stop   chan struct{}
}

func NewProcLifecycleEBPFCollector() *ProcLifecycleEBPFCollector {
	return &ProcLifecycleEBPFCollector{
		// Buffered for fork/exec storms; the sender drops on overflow.
		ch:   make(chan interface{}, 64),
		stop: make(chan struct{}),
	}
}

func (c *ProcLifecycleEBPFCollector) Start(pid int) error {
	tracer, err := bpf.OpenProcTracer(pid)
	if err != nil {
		return fmt.Errorf("proc lifecycle eBPF: %w", err)
	}
	c.tracer = tracer
	// tracer is passed explicitly (not read from the field) so Stop()'s
	// `c.tracer = nil` can't race this goroutine; Close() shuts the ring-buffer
	// reader, unblocking Next with io.EOF.
	go c.readLoop(tracer)
	return nil
}

func (c *ProcLifecycleEBPFCollector) Stop() {
	close(c.stop)
	if c.tracer != nil {
		_ = c.tracer.Close()
		c.tracer = nil
	}
}

func (c *ProcLifecycleEBPFCollector) Subscribe() <-chan interface{} { return c.ch }

// readLoop drains the lifecycle ring buffer, decoding each record into a
// ProcLifecycleEvent and publishing it. It exits on io.EOF (tracer closed). A
// garbled record is logged-by-skip. Sends are non-blocking: under backpressure
// events are dropped, consistent with every other collector.
func (c *ProcLifecycleEBPFCollector) readLoop(tracer *bpf.ProcTracer) {
	if tracer == nil {
		return
	}
	for {
		rec, err := tracer.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			continue // transient (short/garbled record) — keep reading
		}
		ev := decodeProcLifecycle(time.Now(), rec.Kind, rec.PID, rec.PPID,
			rec.Comm[:], rec.Filename[:])
		select {
		case c.ch <- ev:
		default:
		}
	}
}
