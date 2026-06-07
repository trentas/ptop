package serve

import (
	"context"
	"sync"

	"github.com/trentas/ptop/pkg/collector"
	pb "github.com/trentas/ptop/pkg/streampb"
)

// Hub fans collector events in from many channels and out to many Sinks. One
// Hub per server instance (one target PID). Sinks are interchangeable consumers
// of the unified event stream: a gRPC subscriber and a JSONL writer are both
// just Sinks (see sink.go).
type Hub struct {
	pid   int
	mu    sync.Mutex
	sinks map[Sink]struct{}
}

func NewHub(pid int) *Hub {
	return &Hub{pid: pid, sinks: make(map[Sink]struct{})}
}

// Start launches one fan-in goroutine per collector. Each maps published values
// to Events and broadcasts them to every sink. The goroutines exit when ctx is
// cancelled or their source channel closes. Non-blocking — returns immediately.
func (h *Hub) Start(ctx context.Context, cols []collector.Collector) {
	for _, c := range cols {
		ch := c.Subscribe()
		if ch == nil {
			continue
		}
		go h.drain(ctx, ch)
	}
}

func (h *Hub) drain(ctx context.Context, ch <-chan interface{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case v, ok := <-ch:
			if !ok {
				return
			}
			if ev := toEvent(h.pid, v); ev != nil {
				h.broadcast(ev)
			}
		}
	}
}

// broadcast hands the event to every sink. Emit must not block (sinks own their
// buffering), so the collector drain path is never stalled by a slow consumer.
func (h *Hub) broadcast(ev *pb.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.sinks {
		s.Emit(ev)
	}
}

// AddSink registers a sink to receive subsequent events.
func (h *Hub) AddSink(s Sink) {
	h.mu.Lock()
	h.sinks[s] = struct{}{}
	h.mu.Unlock()
}

// RemoveSink stops a sink from receiving events. After it returns, broadcast no
// longer references the sink.
func (h *Hub) RemoveSink(s Sink) {
	h.mu.Lock()
	delete(h.sinks, s)
	h.mu.Unlock()
}

// subscribe registers a gRPC client (a grpcSink) with an optional category
// filter and returns it. Thin helper over AddSink used by the service.
func (h *Hub) subscribe(cats []pb.Category) *grpcSink {
	s := newGRPCSink(cats)
	h.AddSink(s)
	return s
}

func (h *Hub) unsubscribe(s *grpcSink) { h.RemoveSink(s) }

func (h *Hub) sinkCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.sinks)
}
