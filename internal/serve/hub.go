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
	pid     int
	buildID string // target exec build-id, stamped onto every StackRef (#54)
	mu      sync.Mutex
	sinks   map[Sink]struct{}

	// Execution-context identity (#60) stamped onto every outgoing envelope.
	// Updated whenever a ProcContext snapshot flows through; zero until the
	// first one is observed (and on platforms without /proc).
	identMu  sync.Mutex
	uid, gid uint32
	cgroupID uint64
}

func NewHub(pid int, buildID string) *Hub {
	return &Hub{pid: pid, buildID: buildID, sinks: make(map[Sink]struct{})}
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
			// A ProcContext refreshes the cached identity before it (and every
			// subsequent event) is stamped — so the snapshot event itself
			// carries its own up-to-date uid/gid/cgroup_id.
			if pc, ok := v.(collector.ProcContext); ok {
				h.setIdent(pc)
			}
			if ev := toEvent(h.pid, h.buildID, v); ev != nil {
				h.stampIdent(ev)
				h.broadcast(ev)
			}
		}
	}
}

// setIdent updates the cached execution-context identity from a ProcContext
// snapshot (#60).
func (h *Hub) setIdent(pc collector.ProcContext) {
	h.identMu.Lock()
	h.uid, h.gid, h.cgroupID = pc.UID, pc.GID, pc.CgroupID
	h.identMu.Unlock()
}

// stampIdent writes the cached identity onto an event envelope. Values are 0
// until the first ProcContext arrives (and where /proc is unavailable).
func (h *Hub) stampIdent(ev *pb.Event) {
	h.identMu.Lock()
	ev.Uid, ev.Gid, ev.CgroupId = h.uid, h.gid, h.cgroupID
	h.identMu.Unlock()
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
