package serve

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/trentas/ptop/pkg/collector"
	pb "github.com/trentas/ptop/pkg/streampb"
)

// subBuffer bounds each subscriber's queue. A subscriber that can't keep up has
// events dropped (counted), never blocking the collector or growing unbounded.
const subBuffer = 256

// subscriber is one connected client. ch is its bounded queue; filter (nil =
// all) restricts categories; dropped counts events shed under backpressure
// (read atomically by the service goroutine to emit StreamMeta).
type subscriber struct {
	ch      chan *pb.SubscribeResponse
	filter  map[pb.Category]bool
	dropped uint64
}

func (s *subscriber) wants(c pb.Category) bool {
	return s.filter == nil || s.filter[c]
}

// Hub fans collector events in from many channels and out to many subscribers.
// One Hub per server instance (one target PID).
type Hub struct {
	pid  int
	mu   sync.Mutex
	subs map[*subscriber]struct{}
}

func NewHub(pid int) *Hub {
	return &Hub{pid: pid, subs: make(map[*subscriber]struct{})}
}

// Start launches one fan-in goroutine per collector. Each maps published values
// to Events and broadcasts them. The goroutines exit when ctx is cancelled or
// their source channel closes. Non-blocking — returns immediately.
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

func (h *Hub) broadcast(ev *pb.Event) {
	resp := &pb.SubscribeResponse{Kind: &pb.SubscribeResponse_Event{Event: ev}}
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		if !s.wants(ev.GetCategory()) {
			continue
		}
		select {
		case s.ch <- resp:
		default:
			// Slow consumer: shed the event and count it. The service goroutine
			// surfaces the count as a StreamMeta.
			atomic.AddUint64(&s.dropped, 1)
		}
	}
}

// subscribe registers a client with an optional category filter.
func (h *Hub) subscribe(cats []pb.Category) *subscriber {
	s := &subscriber{ch: make(chan *pb.SubscribeResponse, subBuffer)}
	if len(cats) > 0 {
		s.filter = make(map[pb.Category]bool, len(cats))
		for _, c := range cats {
			s.filter[c] = true
		}
	}
	h.mu.Lock()
	h.subs[s] = struct{}{}
	h.mu.Unlock()
	return s
}

// unsubscribe removes a client. After this returns, broadcast no longer
// references the subscriber, so its channel can be abandoned safely.
func (h *Hub) unsubscribe(s *subscriber) {
	h.mu.Lock()
	delete(h.subs, s)
	h.mu.Unlock()
}

func (h *Hub) subscriberCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}
