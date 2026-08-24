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
// unbounded. WHICH events it drops is not first-come-first-served — see
// shed.go, which reserves the tail of the queue for the periodic snapshots so
// an unbounded-rate axis cannot starve them out of the stream.
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
	// admits keeps a flood of per-occurrence events out of the tail of the
	// queue, so the once-a-second snapshots still get through (#108).
	if !admits(len(s.ch), ev) {
		atomic.AddUint64(&s.dropped, 1)
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

// jsonlSink writes the event stream to a file as one protojson
// SubscribeResponse per line — the same message a gRPC subscriber receives, in
// the same order. A bounded channel + writer goroutine keep disk I/O off the
// hub's broadcast path.
//
// Being the same message type is the point: one parser reads either surface,
// and everything the stream says gets said in the file too.
//
//   - The first line is a meta carrying TargetInfo, mirroring the subscriber
//     handshake. Without it an export is unattributable after the fact —
//     nothing in a file of cgroup-mode events says which cgroup produced them,
//     since the envelope pid is 0 there and several payloads carry no pid.
//   - A meta with dropped>0 is written whenever the counter advances, exactly
//     as the gRPC path does. A slow disk used to hole the file silently, with
//     only a stderr line at Close to say so — and an unrecorded gap in an
//     export read months later is worse than a recorded one, because a
//     deploy-vs-deploy comparison reads the hole as a behavior change.
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
		if err := writeJSONLLine(w, metaResponse(&pb.StreamMeta{Target: target})); err != nil {
			return nil, fmt.Errorf("serve: jsonl target header: %w", err)
		}
	}
	s := &jsonlSink{w: w, ch: make(chan *pb.Event, subBuffer), done: make(chan struct{})}
	go s.run()
	return s, nil
}

// jsonlMarshal keeps every line on identical marshalling terms: compact, one
// object per line.
var jsonlMarshal = protojson.MarshalOptions{}

func metaResponse(m *pb.StreamMeta) *pb.SubscribeResponse {
	return &pb.SubscribeResponse{Kind: &pb.SubscribeResponse_Meta{Meta: m}}
}

func eventResponse(ev *pb.Event) *pb.SubscribeResponse {
	return &pb.SubscribeResponse{Kind: &pb.SubscribeResponse_Event{Event: ev}}
}

func writeJSONLLine(w io.Writer, resp *pb.SubscribeResponse) error {
	b, err := jsonlMarshal.Marshal(resp)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

func (s *jsonlSink) Emit(ev *pb.Event) {
	if !admits(len(s.ch), ev) { // see shed.go
		atomic.AddUint64(&s.dropped, 1)
		return
	}
	select {
	case s.ch <- ev:
	default:
		atomic.AddUint64(&s.dropped, 1)
	}
}

func (s *jsonlSink) run() {
	defer close(s.done)

	var reported uint64
	for ev := range s.ch {
		// Same policy as the gRPC path (see service.Subscribe): when the drop
		// counter has advanced, a meta goes out ahead of the next event, so the
		// gap is recorded where it happened.
		if cur := atomic.LoadUint64(&s.dropped); cur != reported {
			reported = cur
			if !s.writeLine(metaResponse(&pb.StreamMeta{Dropped: cur})) {
				return
			}
		}
		if !s.writeLine(eventResponse(ev)) {
			return
		}
	}

	// Drops after the last event still belong in the file.
	if cur := atomic.LoadUint64(&s.dropped); cur != reported {
		s.writeLine(metaResponse(&pb.StreamMeta{Dropped: cur}))
	}
}

// writeLine reports whether the writer is still usable: a value that cannot be
// marshalled is skipped, while a failed write ends the goroutine, since every
// line after it would fail the same way.
func (s *jsonlSink) writeLine(resp *pb.SubscribeResponse) bool {
	b, err := jsonlMarshal.Marshal(resp)
	if err != nil {
		return true
	}
	if _, err := s.w.Write(append(b, '\n')); err != nil {
		fmt.Fprintf(os.Stderr, "warning: jsonl export write: %v\n", err)
		return false
	}
	return true
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
