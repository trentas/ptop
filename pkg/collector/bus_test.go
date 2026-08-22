package collector

import (
	"context"
	"testing"
	"time"
)

// fakeCollector publishes whatever the test feeds it, on the single shared
// channel every real collector hands out.
type fakeCollector struct{ ch chan interface{} }

func newFakeCollector(buf int) *fakeCollector {
	return &fakeCollector{ch: make(chan interface{}, buf)}
}

func (f *fakeCollector) Start(int) error               { return nil }
func (f *fakeCollector) Stop()                         { close(f.ch) }
func (f *fakeCollector) Subscribe() <-chan interface{} { return f.ch }

// The whole point of the bus: two consumers of one collector both see every
// value, instead of splitting the stream between them.
func TestBusFansOutToEveryConsumer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f := newFakeCollector(8)
	bus := NewBus()
	bus.Start(ctx, []Collector{f})

	a := bus.Subscribe(8)
	defer a.Close()
	b := bus.Subscribe(8)
	defer b.Close()

	var inline []interface{}
	done := make(chan struct{}, 4)
	bus.AddHandler(func(v interface{}) { inline = append(inline, v); done <- struct{}{} })

	for i := 0; i < 3; i++ {
		f.ch <- CpuSample{UsagePct: float64(i)}
	}
	for i := 0; i < 3; i++ {
		<-done // the inline handler runs on the drain goroutine; wait for it
	}

	for name, sub := range map[string]*Subscription{"a": a, "b": b} {
		for i := 0; i < 3; i++ {
			v := recvValue(t, sub)
			s, ok := v.(CpuSample)
			if !ok || s.UsagePct != float64(i) {
				t.Fatalf("%s got %#v, want CpuSample{%d}", name, v, i)
			}
		}
	}
	if len(inline) != 3 {
		t.Errorf("inline handler saw %d values, want 3", len(inline))
	}
}

// A consumer that stops reading must lose events and count them — never stall
// the collectors, and never hide the gap.
func TestBusSlowConsumerDropsAndCounts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f := newFakeCollector(1)
	bus := NewBus()
	bus.Start(ctx, []Collector{f})

	slow := bus.Subscribe(2)
	defer slow.Close()
	fast := bus.Subscribe(64)
	defer fast.Close()

	for i := 0; i < 20; i++ {
		f.ch <- CpuSample{UsagePct: float64(i)}
	}
	// The fast consumer draining all 20 proves the producer was never blocked
	// by the slow one.
	for i := 0; i < 20; i++ {
		recvValue(t, fast)
	}
	if got := slow.Dropped(); got == 0 {
		t.Error("slow consumer dropped nothing; expected the bounded queue to shed")
	}
	if got := fast.Dropped(); got != 0 {
		t.Errorf("fast consumer dropped %d, want 0", got)
	}
}

// Close must unregister before closing the channel, or a broadcast racing it
// would send on a closed channel and panic.
func TestSubscriptionCloseIsSafeAndIdempotent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f := newFakeCollector(64)
	bus := NewBus()
	bus.Start(ctx, []Collector{f})

	sub := bus.Subscribe(4)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				f.ch <- CpuSample{}
			}
		}
	}()

	sub.Close()
	sub.Close() // idempotent
	close(stop)

	if _, open := <-sub.C(); open {
		t.Error("channel still delivering after Close")
	}
	if n := bus.HandlerCount(); n != 0 {
		t.Errorf("HandlerCount = %d after Close, want 0", n)
	}
}

// A removed handler must not be called again — RemoveHandler waits for the
// in-flight broadcast rather than racing it.
func TestRemoveHandlerStopsDelivery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f := newFakeCollector(8)
	bus := NewBus()
	bus.Start(ctx, []Collector{f})

	seen := make(chan struct{}, 16)
	h := bus.AddHandler(func(interface{}) { seen <- struct{}{} })
	f.ch <- CpuSample{}
	<-seen

	bus.RemoveHandler(h)
	sentinel := bus.Subscribe(4) // ordering probe: it is attached after h left
	defer sentinel.Close()

	f.ch <- CpuSample{}
	recvValue(t, sentinel) // the value has now been broadcast
	select {
	case <-seen:
		t.Error("removed handler still received a value")
	default:
	}
}

// Cancelling the context stops the drain goroutines.
func TestBusStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := newFakeCollector(8)
	bus := NewBus()
	bus.Start(ctx, []Collector{f})

	sub := bus.Subscribe(8)
	defer sub.Close()
	f.ch <- CpuSample{UsagePct: 1}
	recvValue(t, sub)

	cancel()
	// Give the drain goroutine a moment to observe the cancellation, then check
	// that further publishes go nowhere.
	deadline := time.After(time.Second)
	for {
		f.ch <- CpuSample{UsagePct: 2}
		select {
		case <-sub.C():
			select {
			case <-deadline:
				t.Fatal("drain goroutine still broadcasting after cancel")
			default:
				continue // may still be draining what was queued
			}
		case <-time.After(100 * time.Millisecond):
			return // nothing arrived: the drain goroutine is gone
		}
	}
}

// A stub collector (Subscribe returns nil off Linux / without eBPF) must be
// skipped, not panic the drain.
func TestBusSkipsNilChannels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus := NewBus()
	bus.Start(ctx, []Collector{stubCollector{}})
	if n := bus.HandlerCount(); n != 0 {
		t.Errorf("HandlerCount = %d, want 0", n)
	}
}

type stubCollector struct{}

func (stubCollector) Start(int) error               { return nil }
func (stubCollector) Stop()                         {}
func (stubCollector) Subscribe() <-chan interface{} { return nil }

func recvValue(t *testing.T, s *Subscription) interface{} {
	t.Helper()
	select {
	case v, ok := <-s.C():
		if !ok {
			t.Fatal("subscription channel closed")
		}
		return v
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a value")
		return nil
	}
}
