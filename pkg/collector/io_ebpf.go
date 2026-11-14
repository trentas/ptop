//go:build linux && ebpf

package collector

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/trentas/ptop/internal/bpf"
)

// IOEBPFCollector publishes the eBPF io probe's per-file counts and latency
// histogram every 500ms (IOStats.TopFiles + LatencyBuckets), and its fs events
// as they happen (#57).
//
// The probe counts reads and writes in the kernel (#181); ioAgg says how they
// become rows. A file is named as it was when the call ran, from the open that
// installed its fd or from the fd's link checked against the call's inode
// (fileNames, #162). One it cannot name is "fd=N".
type IOEBPFCollector struct {
	tracer   *bpf.IOTracer
	ch       chan interface{}
	wg       sync.WaitGroup
	stopOnce sync.Once
}

const (
	ioWindow = 500 * time.Millisecond
	// ioDrainBudget bounds the ring drain at a window's end, so a burst of
	// opens cannot hold a snapshot back.
	ioDrainBudget = 50 * time.Millisecond
)

func NewIOEBPFCollector() *IOEBPFCollector {
	return &IOEBPFCollector{
		// Buffered for the 500ms snapshot plus bursty per-event fs events
		// (#57); all senders drop on overflow.
		ch: make(chan interface{}, 64),
	}
}

func (c *IOEBPFCollector) Start(pid int) error { return c.start(bpf.TargetPID(pid), pid) }

// StartCgroup tracks I/O across a whole cgroup subtree instead of one pid
// (#94). Implements CgroupTargeter.
//
// Byte counters and latency histograms are unaffected, but top files are named
// "fd=N": naming one means reading /proc/<pid>/fd/<n>, and a subtree has no
// single pid to read it from (fileNames).
func (c *IOEBPFCollector) StartCgroup(spec string) error {
	return c.start(bpf.TargetCgroup(spec), 0)
}

func (c *IOEBPFCollector) start(t bpf.Target, pid int) error {
	tracer, err := bpf.OpenIOTracer(t)
	if err != nil {
		return fmt.Errorf("io eBPF: %w", err)
	}
	c.tracer = tracer
	c.wg.Add(2)
	go c.loop(tracer, newIOAgg(pid))
	go c.fsReadLoop(tracer)
	return nil
}

// Stop interrupts both loops, waits for them, and only then closes the tracer:
// the loop reads the maps between ring reads. Idempotent, and safe when Start
// failed.
func (c *IOEBPFCollector) Stop() {
	c.stopOnce.Do(func() {
		if c.tracer == nil {
			return
		}
		c.tracer.Interrupt()
		c.wg.Wait()
		_ = c.tracer.Close()
	})
}

func (c *IOEBPFCollector) Subscribe() <-chan interface{} {
	return c.ch
}

// loop reads the ring until each window ends, then reads the maps and
// publishes a snapshot. It exits when the tracer is interrupted.
func (c *IOEBPFCollector) loop(t *bpf.IOTracer, a *ioAgg) {
	defer c.wg.Done()
	next := time.Now().Add(ioWindow)
	t.SetDeadline(next)
	for {
		r, err := t.Next()
		switch {
		case err == nil:
			a.record(r, time.Now())
		case errors.Is(err, io.EOF):
			return
		}
		// A deadline, a record, or a short one: the window may be over either
		// way, and a stream that never pauses must not hold it open.
		if time.Now().Before(next) {
			continue
		}
		if !c.window(t, a) {
			return
		}
		next = next.Add(ioWindow)
		if now := time.Now(); !next.After(now) {
			next = now.Add(ioWindow)
		}
		t.SetDeadline(next)
	}
}

// window reads the maps, drains the ring, folds, and publishes. The map is read
// BEFORE the drain: every key in that read was created after the open naming
// it was recorded, so the drain delivers the name before the key is folded.
// Returns false when the tracer was interrupted.
func (c *IOEBPFCollector) window(t *bpf.IOTracer, a *ioAgg) bool {
	stats, serr := t.Stats()
	totals, terr := t.Totals()

	now := time.Now()
	t.SetDeadline(now)
	caughtUp := false
	for !caughtUp && time.Since(now) < ioDrainBudget {
		r, err := t.Next()
		switch {
		case err == nil:
			a.record(r, time.Now())
		case errors.Is(err, io.EOF):
			return false
		case errors.Is(err, os.ErrDeadlineExceeded):
			caughtUp = true
		}
	}

	now = time.Now()
	if serr == nil {
		for _, k := range a.read(stats, now, caughtUp) {
			if v, ok, err := t.RetireStat(k); err == nil && ok {
				a.retired(k, v, now)
			}
		}
	}
	publish(c.ch, a.snapshot(totals, terr == nil))
	return true
}

// fsReadLoop drains the fs-semantics ring buffer (#57), decoding each record
// into an FSEvent and publishing it on the shared channel. It exits on io.EOF
// (the tracer was interrupted). A garbled record is logged-by-skip — the
// stream continues. Sends are non-blocking: under backpressure fs events are
// dropped, consistent with every other collector.
func (c *IOEBPFCollector) fsReadLoop(tracer *bpf.IOTracer) {
	defer c.wg.Done()
	for {
		rec, err := tracer.NextFSEvent()
		if err != nil {
			if err == io.EOF {
				return
			}
			continue // transient (short/garbled record) — keep reading
		}
		fe := decodeFSEvent(time.Now(), rec.Op, rec.Ret, rec.Path[:], rec.NewPath[:])
		publish(c.ch, fe)
	}
}
