//go:build linux && ebpf

package collector

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/trentas/ptop/internal/bpf"
)

// TLSEBPFCollector consumes the tls_events ring buffer of the eBPF TLS tracer
// and publishes one TLSPayload per SSL_write/SSL_read of the target (#55).
// eBPF-only, opt-in (--tls), never simulated. maxBytes bounds the plaintext
// copied per call (0 = metadata only).
type TLSEBPFCollector struct {
	tracer   *bpf.TLSTracer
	maxBytes int
	ch       chan interface{}
	stop     chan struct{}
}

func NewTLSEBPFCollector(maxBytes int) *TLSEBPFCollector {
	return &TLSEBPFCollector{
		maxBytes: maxBytes,
		// Buffered for bursty TLS traffic; the sender drops on overflow.
		ch:   make(chan interface{}, 64),
		stop: make(chan struct{}),
	}
}

func (c *TLSEBPFCollector) Start(pid int) error {
	tracer, err := bpf.OpenTLSTracer(pid, c.maxBytes)
	if err != nil {
		return fmt.Errorf("tls eBPF: %w", err)
	}
	c.tracer = tracer
	// Drain payload events. tracer is passed explicitly (not read from the
	// field) so Stop()'s `c.tracer = nil` can't race this goroutine; Close()
	// shuts the ring-buffer reader, unblocking Next with io.EOF.
	go c.readLoop(tracer)
	return nil
}

func (c *TLSEBPFCollector) Stop() {
	close(c.stop)
	if c.tracer != nil {
		_ = c.tracer.Close()
		c.tracer = nil
	}
}

func (c *TLSEBPFCollector) Subscribe() <-chan interface{} {
	return c.ch
}

// readLoop drains the ring buffer, decoding each record into a TLSPayload and
// publishing it. It exits on io.EOF (the tracer was closed). A garbled record is
// logged-by-skip. Sends are non-blocking: under backpressure payloads are
// dropped, consistent with every other collector.
func (c *TLSEBPFCollector) readLoop(tracer *bpf.TLSTracer) {
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
		p := decodeTLS(time.Now(), rec.Dir, rec.FD, rec.Len, rec.Captured, rec.Data[:])
		select {
		case c.ch <- p:
		default:
		}
	}
}
