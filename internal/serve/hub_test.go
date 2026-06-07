package serve

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trentas/ptop/pkg/collector"
	pb "github.com/trentas/ptop/pkg/streampb"
)

// fakeCollector is a test Collector whose channel the test drives directly.
type fakeCollector struct{ ch chan interface{} }

func newFake(buf int) *fakeCollector { return &fakeCollector{ch: make(chan interface{}, buf)} }

func (f *fakeCollector) Start(int) error               { return nil }
func (f *fakeCollector) Stop()                         {}
func (f *fakeCollector) Subscribe() <-chan interface{} { return f.ch }

func TestHubFanOut(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f := newFake(8)
	h := NewHub(7)
	sub := h.subscribe(nil)
	h.Start(ctx, []collector.Collector{f})

	f.ch <- collector.CpuSample{UsagePct: 50, Timestamp: time.Now()}

	select {
	case resp := <-sub.ch:
		ev := resp.GetEvent()
		if ev == nil {
			t.Fatalf("expected an event, got %v", resp)
		}
		if ev.GetCategory() != pb.Category_CATEGORY_CPU {
			t.Errorf("category = %v, want CPU", ev.GetCategory())
		}
		if ev.GetPid() != 7 {
			t.Errorf("pid = %d, want 7", ev.GetPid())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestHubCategoryFilter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f := newFake(8)
	h := NewHub(1)
	sub := h.subscribe([]pb.Category{pb.Category_CATEGORY_NETWORK})
	h.Start(ctx, []collector.Collector{f})

	// CPU is filtered out; the network snapshot gets through. So the first (and
	// only) thing the subscriber sees must be the network event.
	f.ch <- collector.CpuSample{UsagePct: 1, Timestamp: time.Now()}
	f.ch <- []collector.NetConn{{FD: 3, Type: "TCP"}}

	select {
	case resp := <-sub.ch:
		if c := resp.GetEvent().GetCategory(); c != pb.Category_CATEGORY_NETWORK {
			t.Errorf("category = %v, want NETWORK (CPU should have been filtered)", c)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for network event")
	}

	// Nothing else should be queued (CPU was dropped by the filter, not buffered).
	select {
	case resp := <-sub.ch:
		t.Errorf("unexpected extra response: %v", resp)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestHubBackpressureDrops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Source channel large enough to hold every emit without blocking the test.
	f := newFake(subBuffer + 200)
	h := NewHub(1)
	sub := h.subscribe(nil) // never read → its buffer fills, then drops
	h.Start(ctx, []collector.Collector{f})

	const n = subBuffer + 100
	for i := 0; i < n; i++ {
		f.ch <- collector.CpuSample{UsagePct: float64(i), Timestamp: time.Now()}
	}

	// Wait for the drain goroutine to fill sub.ch and start dropping.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadUint64(&sub.dropped) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if d := atomic.LoadUint64(&sub.dropped); d == 0 {
		t.Fatalf("expected drops under backpressure, got 0")
	}
}

func TestHubUnsubscribe(t *testing.T) {
	h := NewHub(1)
	sub := h.subscribe(nil)
	if h.sinkCount() != 1 {
		t.Fatalf("count = %d, want 1", h.sinkCount())
	}
	h.unsubscribe(sub)
	if h.sinkCount() != 0 {
		t.Fatalf("count = %d, want 0 after unsubscribe", h.sinkCount())
	}
}
