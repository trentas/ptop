//go:build linux && ebpf

package collector

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/trentas/ptop/internal/bpf"
)

// SignalEBPFCollector consumes the signal:signal_generate ring buffer of the
// eBPF signal tracer and publishes one SignalEvent per signal delivered to the
// target — including the sender (#58). There is no /proc fallback and no
// simulation: signals are surfaced only when eBPF can attach the tracepoint.
type SignalEBPFCollector struct {
	tracer *bpf.SignalTracer
	ch     chan interface{}
	stop   chan struct{}
}

func NewSignalEBPFCollector() *SignalEBPFCollector {
	return &SignalEBPFCollector{
		// Buffered for bursty signal storms; the sender drops on overflow.
		ch:   make(chan interface{}, 64),
		stop: make(chan struct{}),
	}
}

func (c *SignalEBPFCollector) Start(pid int) error {
	tracer, err := bpf.OpenSignalTracer(pid)
	if err != nil {
		return fmt.Errorf("signal eBPF: %w", err)
	}
	c.tracer = tracer
	// Drain signal events. tracer is passed explicitly (not read from the field)
	// so Stop()'s `c.tracer = nil` can't race this goroutine; Close() shuts the
	// ring-buffer reader, unblocking Next with io.EOF.
	go c.readLoop(tracer)
	return nil
}

func (c *SignalEBPFCollector) Stop() {
	close(c.stop)
	if c.tracer != nil {
		_ = c.tracer.Close()
		c.tracer = nil
	}
}

func (c *SignalEBPFCollector) Subscribe() <-chan interface{} {
	return c.ch
}

// readLoop drains the signal ring buffer, decoding each record into a
// SignalEvent and publishing it on the channel. It exits on io.EOF (the tracer
// was closed). A garbled record is logged-by-skip — the stream continues. Sends
// are non-blocking: under backpressure signals are dropped, consistent with
// every other collector.
func (c *SignalEBPFCollector) readLoop(tracer *bpf.SignalTracer) {
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
		se := decodeSignal(time.Now(), int32(rec.Signo), int32(rec.SenderPID),
			int32(rec.TargetTID), rec.Code, int32(rec.Result), rec.SenderComm[:])
		select {
		case c.ch <- se:
		default:
		}
	}
}
