package collector

import (
	"context"
	"sync"
	"sync/atomic"
)

// Bus is the single fan-out over a running set of collectors (#71).
//
// A collector's Subscribe() hands out ONE shared channel, so two direct readers
// steal each other's values — each sees roughly half the stream. The Bus reads
// every collector exactly once and re-broadcasts what it publishes, which is
// what lets the TUI, the JSONL export and any number of gRPC subscribers
// consume the same running collectors at the same time.
//
// Two consumer styles share one bus:
//
//   - AddHandler — called inline on the drain goroutine. No queue, so nothing
//     is ever dropped on the way in, and therefore the handler MUST NOT block:
//     it is for a consumer that transforms and hands off immediately (the
//     headless hub maps to an Event and gives it to its sinks, which own their
//     own buffering).
//   - Subscribe — a bounded channel for a consumer with its own loop (the TUI).
//     A consumer that falls behind has values dropped and counted, rather than
//     stalling the collectors behind it.
//
// The zero value is not usable; call NewBus (or StartFeed).
type Bus struct {
	mu       sync.RWMutex
	handlers map[*Handler]struct{}
}

// Handler is one registered inline consumer. Keep the returned pointer to
// unregister it later.
type Handler struct{ fn func(v interface{}) }

func NewBus() *Bus { return &Bus{handlers: make(map[*Handler]struct{})} }

// StartBus builds a Bus over cols and starts draining them — the one-liner for
// callers that already have their collectors (StartFeed builds the Set too).
func StartBus(ctx context.Context, cols []Collector) *Bus {
	b := NewBus()
	b.Start(ctx, cols)
	return b
}

// Start drains every collector in cols exactly once and broadcasts whatever
// they publish. One goroutine per collector, each ending when ctx is cancelled
// or its channel closes. Returns immediately.
//
// Ordering is per collector: values from one collector reach every consumer in
// publish order. Across collectors there is no ordering — the same as reading
// their channels directly.
//
// Start must be called once per set of collectors. Starting a second Bus over
// collectors already being drained brings back exactly the event-stealing this
// type exists to prevent.
func (b *Bus) Start(ctx context.Context, cols []Collector) {
	for _, c := range cols {
		ch := c.Subscribe()
		if ch == nil {
			continue // stub collector (non-Linux / no-ebpf build)
		}
		go b.drain(ctx, ch)
	}
}

func (b *Bus) drain(ctx context.Context, ch <-chan interface{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case v, ok := <-ch:
			if !ok {
				return
			}
			b.broadcast(v)
		}
	}
}

func (b *Bus) broadcast(v interface{}) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for h := range b.handlers {
		h.fn(v)
	}
}

// AddHandler registers fn to be called with every published value, inline on
// the drain goroutine. fn must not block.
func (b *Bus) AddHandler(fn func(v interface{})) *Handler {
	h := &Handler{fn: fn}
	b.mu.Lock()
	b.handlers[h] = struct{}{}
	b.mu.Unlock()
	return h
}

// RemoveHandler stops a handler from receiving values. It takes the write lock,
// so it waits for any in-flight broadcast to finish: once it returns the
// handler is neither running nor about to run. That is what makes closing a
// subscription's channel safe.
func (b *Bus) RemoveHandler(h *Handler) {
	if h == nil {
		return
	}
	b.mu.Lock()
	delete(b.handlers, h)
	b.mu.Unlock()
}

// HandlerCount reports how many consumers are attached.
func (b *Bus) HandlerCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.handlers)
}

// Subscription is a channel-style consumer with its own bounded queue. Values
// arriving while the queue is full are dropped and counted — a slow consumer
// loses events, it never slows the collectors down.
type Subscription struct {
	bus     *Bus
	h       *Handler
	ch      chan interface{}
	dropped atomic.Uint64
	once    sync.Once
}

// Subscribe registers a channel consumer with a queue of the given size
// (buffer < 1 is raised to 1).
func (b *Bus) Subscribe(buffer int) *Subscription {
	if buffer < 1 {
		buffer = 1
	}
	s := &Subscription{bus: b, ch: make(chan interface{}, buffer)}
	s.h = b.AddHandler(func(v interface{}) {
		select {
		case s.ch <- v:
		default:
			s.dropped.Add(1)
		}
	})
	return s
}

// C is the subscription's queue. Close closes it, so a consumer loop should
// treat a closed channel as "the feed is done".
func (s *Subscription) C() <-chan interface{} { return s.ch }

// Dropped is how many values this consumer missed by falling behind.
// Cumulative, never reset — report gaps, never hide them.
func (s *Subscription) Dropped() uint64 { return s.dropped.Load() }

// Close unregisters the subscription and closes its channel. Idempotent, and
// safe against a concurrent broadcast (RemoveHandler waits for it to finish).
func (s *Subscription) Close() {
	s.once.Do(func() {
		s.bus.RemoveHandler(s.h)
		close(s.ch)
	})
}

// Feed pairs a running Set with the Bus fanning it out. The two always travel
// together: handing them around separately invites the bug this package exists
// to prevent — a second Bus built over collectors already being drained, with
// the two stealing each other's values.
type Feed struct {
	Set *Set
	Bus *Bus
}

// StartFeed builds the Set for cfg, starts its collectors and begins draining
// them onto a Bus. The caller owns the lifecycle: cancel ctx to stop the drain
// goroutines and call Feed.Stop to release the collectors.
func StartFeed(ctx context.Context, cfg SetConfig) *Feed {
	set := NewSet(cfg)
	return &Feed{Set: set, Bus: StartBus(ctx, set.Collectors())}
}

// Stop releases the collectors (idempotent, like Set.Stop). The bus's drain
// goroutines end on their own once the collector channels close or the context
// passed to StartFeed is cancelled.
func (f *Feed) Stop() {
	if f == nil || f.Set == nil {
		return
	}
	f.Set.Stop()
}
