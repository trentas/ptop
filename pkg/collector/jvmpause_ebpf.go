//go:build linux && ebpf

package collector

import (
	"time"

	"github.com/trentas/ptop/internal/bpf"
)

// JVMPauseEBPFCollector publishes a HotSpot JVM's stop-the-world pauses every
// second (#189): each lane's cumulative count, sum and log2(µs) histogram, so
// a consumer takes the difference for any window and a dropped sample loses
// nothing — the GoPauses contract.
type JVMPauseEBPFCollector struct {
	tracer         *bpf.JVMPauseTracer
	safepoints, gc bool
	ch             chan interface{}
	stop           chan struct{}
	done           chan struct{}
}

func NewJVMPauseEBPFCollector() *JVMPauseEBPFCollector {
	return &JVMPauseEBPFCollector{ch: make(chan interface{}, 8), stop: make(chan struct{}), done: make(chan struct{})}
}

// Start returns an error wrapping bpf.ErrNotJVM for a target with no HotSpot
// libjvm.so: the axis is unsupported there, never an empty one.
func (c *JVMPauseEBPFCollector) Start(pid int) error {
	t, err := bpf.OpenJVMPauseTracer(pid)
	if err != nil {
		return err
	}
	c.tracer = t
	c.safepoints, c.gc = t.Lanes()
	go c.loop()
	return nil
}

// Caveat names the lane that did not attach, so the probe set says the axis is
// half there rather than leaving a missing lane to read as no pauses.
func (c *JVMPauseEBPFCollector) Caveat() string { return c.tracer.Caveat() }

func (c *JVMPauseEBPFCollector) loop() {
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

func (c *JVMPauseEBPFCollector) read() (JVMPauses, error) {
	sp, gc, err := c.tracer.Totals()
	if err != nil {
		return JVMPauses{}, err
	}
	v := JVMPauses{Timestamp: time.Now()}
	if c.safepoints {
		v.Safepoints = pauseHistogram(sp)
	}
	if c.gc {
		v.GC = pauseHistogram(gc)
	}
	return v, nil
}

func pauseHistogram(t bpf.PauseTotals) *PauseHistogram {
	return &PauseHistogram{Count: t.Count, SumNs: t.SumNs, Buckets: append([]uint64(nil), t.Buckets[:]...)}
}

func (c *JVMPauseEBPFCollector) Stop() {
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

func (c *JVMPauseEBPFCollector) Subscribe() <-chan interface{} { return c.ch }
