package serve

import (
	"fmt"
	"io"
	"os"
	"sync/atomic"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/trentas/ptop/pkg/streampb"
)

// subBuffer bounds each sink's queue. A sink that can't keep up has events
// dropped (counted), never blocking the collector drain path or growing
// unbounded.
const subBuffer = 256

// Sink is an interchangeable consumer of the event stream. The gRPC subscriber
// and the JSONL writer are both Sinks. Emit MUST NOT block — sinks own their
// own buffering and shed events when they fall behind — so the hub's broadcast
// (and thus the collector drain) is never stalled by a slow consumer.
type Sink interface {
	Emit(ev *pb.Event)
	Close() error
}

// grpcSink is one connected gRPC client. ch is its bounded queue; filter
// (nil = all) restricts categories; dropped counts events shed under
// backpressure (read atomically by the service goroutine to emit StreamMeta).
type grpcSink struct {
	ch      chan *pb.SubscribeResponse
	filter  map[pb.Category]bool
	dropped uint64
}

func newGRPCSink(cats []pb.Category) *grpcSink {
	s := &grpcSink{ch: make(chan *pb.SubscribeResponse, subBuffer)}
	if len(cats) > 0 {
		s.filter = make(map[pb.Category]bool, len(cats))
		for _, c := range cats {
			s.filter[c] = true
		}
	}
	return s
}

func (s *grpcSink) wants(c pb.Category) bool {
	return s.filter == nil || s.filter[c]
}

func (s *grpcSink) Emit(ev *pb.Event) {
	if !s.wants(ev.GetCategory()) {
		return
	}
	resp := &pb.SubscribeResponse{Kind: &pb.SubscribeResponse_Event{Event: ev}}
	select {
	case s.ch <- resp:
	default:
		atomic.AddUint64(&s.dropped, 1)
	}
}

func (s *grpcSink) Close() error { return nil }

// jsonlSink writes a target header followed by every event as one protojson
// line to a file. A bounded channel + writer goroutine keep disk I/O off the
// hub's broadcast path; on overflow events are dropped and counted (reported on
// Close).
//
// The FIRST line is a StreamMeta carrying TargetInfo, mirroring the handshake a
// gRPC subscriber receives; every line after it is an Event. Without it an
// export is unattributable after the fact — nothing in a file of cgroup-mode
// events says which cgroup produced them, since the envelope pid is 0 there and
// several payloads carry no pid of their own.
type jsonlSink struct {
	w       io.WriteCloser
	ch      chan *pb.Event
	done    chan struct{}
	dropped uint64
}

func newJSONLSink(path string, target *pb.TargetInfo) (*jsonlSink, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	s, err := newJSONLSinkWriter(f, target)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return s, nil
}

// newJSONLSinkWriter is the testable core: it writes to any WriteCloser.
//
// The header is written synchronously, before the writer goroutine starts, so
// it is line 1 whatever the scheduler does — and a file that cannot even take
// its header fails here, at startup, instead of producing a headerless export.
func newJSONLSinkWriter(w io.WriteCloser, target *pb.TargetInfo) (*jsonlSink, error) {
	if target != nil {
		b, err := jsonlMarshal.Marshal(&pb.StreamMeta{Target: target})
		if err != nil {
			return nil, fmt.Errorf("serve: jsonl target header: %w", err)
		}
		if _, err := w.Write(append(b, '\n')); err != nil {
			return nil, fmt.Errorf("serve: jsonl target header: %w", err)
		}
	}
	s := &jsonlSink{w: w, ch: make(chan *pb.Event, subBuffer), done: make(chan struct{})}
	go s.run()
	return s, nil
}

// jsonlMarshal keeps the header and the events on identical marshalling terms:
// compact, one object per line.
var jsonlMarshal = protojson.MarshalOptions{}

func (s *jsonlSink) Emit(ev *pb.Event) {
	select {
	case s.ch <- ev:
	default:
		atomic.AddUint64(&s.dropped, 1)
	}
}

func (s *jsonlSink) run() {
	defer close(s.done)
	for ev := range s.ch {
		b, err := jsonlMarshal.Marshal(ev)
		if err != nil {
			continue
		}
		if _, err := s.w.Write(append(b, '\n')); err != nil {
			fmt.Fprintf(os.Stderr, "warning: jsonl export write: %v\n", err)
			return
		}
	}
}

// Close flushes the queued events and closes the writer. The caller must
// RemoveSink this from the hub first, so no Emit races the channel close.
func (s *jsonlSink) Close() error {
	close(s.ch)
	<-s.done
	if d := atomic.LoadUint64(&s.dropped); d > 0 {
		fmt.Fprintf(os.Stderr, "[ptop] jsonl export dropped %d events (slow disk)\n", d)
	}
	return s.w.Close()
}
