//go:build linux && ebpf

package collector

import (
	"time"

	"github.com/trentas/ptop/internal/bpf"
)

// GoPauseEBPFCollector publishes a Go target's stop-the-world pauses every
// second (#175): the tracer's cumulative count, sum and log2(µs) histogram, so
// a consumer takes the difference for any window and a dropped sample loses
// nothing — the RunqLatency contract.
type GoPauseEBPFCollector struct {
	tracer *bpf.GoPauseTracer
	ch     chan interface{}
	stop   chan struct{}
	done   chan struct{}
}

func NewGoPauseEBPFCollector() *GoPauseEBPFCollector {
	return &GoPauseEBPFCollector{ch: make(chan interface{}, 8), stop: make(chan struct{}), done: make(chan struct{})}
}

// Start returns an error wrapping bpf.ErrNotGo for a target that is not a Go
// program: the axis is unsupported there, never an empty one.
func (c *GoPauseEBPFCollector) Start(pid int) error {
	t, err := bpf.OpenGoPauseTracer(pid)
	if err != nil {
		return err
	}
	c.tracer = t
	go c.loop()
	return nil
}

func (c *GoPauseEBPFCollector) loop() {
	defer close(c.done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-tick.C:
			if v, err := c.read(); err == nil {
				publish(c.ch, v)
			}
		}
	}
}

func (c *GoPauseEBPFCollector) read() (GoPauses, error) {
	t, err := c.tracer.Totals()
	if err != nil {
		return GoPauses{}, err
	}
	return GoPauses{Timestamp: time.Now(), Count: t.Count, SumNs: t.SumNs, Buckets: append([]uint64(nil), t.Buckets[:]...)}, nil
}

func (c *GoPauseEBPFCollector) Stop() {
	select {
	case <-c.stop:
		return
	default:
	}
	close(c.stop)
	if c.tracer != nil {
		<-c.done
		_ = c.tracer.Close()
	}
}

func (c *GoPauseEBPFCollector) Subscribe() <-chan interface{} { return c.ch }
