package serve

import (
	"bufio"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/trentas/ptop/pkg/streampb"
)

// jsonlSink writes one parseable protojson Event per line, and Close flushes
// what's queued.
func TestJSONLSinkRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	s, err := newJSONLSink(path)
	if err != nil {
		t.Fatalf("newJSONLSink: %v", err)
	}

	const n = 20
	for i := 0; i < n; i++ {
		s.Emit(&pb.Event{
			Pid:      7,
			Category: pb.Category_CATEGORY_CPU,
			Payload:  &pb.Event_Cpu{Cpu: &pb.CpuSample{UsagePct: float64(i)}},
		})
	}
	if err := s.Close(); err != nil { // flushes queued events
		t.Fatalf("close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	var lines int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev pb.Event
		if err := protojson.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("line %d not valid protojson Event: %v", lines, err)
		}
		if ev.GetPid() != 7 || ev.GetCategory() != pb.Category_CATEGORY_CPU {
			t.Errorf("line %d: unexpected event %v", lines, &ev)
		}
		lines++
	}
	if lines != n {
		t.Errorf("got %d lines, want %d", lines, n)
	}
}

// blockingWriter blocks every Write until release is closed, so the sink's
// writer goroutine stalls and the bounded channel overflows.
type blockingWriter struct {
	release chan struct{}
	mu      sync.Mutex
	written int
}

func (w *blockingWriter) Write(p []byte) (int, error) {
	<-w.release
	w.mu.Lock()
	w.written += len(p)
	w.mu.Unlock()
	return len(p), nil
}
func (w *blockingWriter) Close() error { return nil }

// A stalled writer must cause drops (counted), never block the Emit caller.
func TestJSONLSinkDropsWhenWriterBlocked(t *testing.T) {
	bw := &blockingWriter{release: make(chan struct{})}
	s := newJSONLSinkWriter(bw)

	// Emit far more than the buffer while the writer is blocked. Emit must never
	// block, so this returns promptly.
	const n = subBuffer + 200
	done := make(chan struct{})
	go func() {
		for i := 0; i < n; i++ {
			s.Emit(&pb.Event{Pid: 1, Category: pb.Category_CATEGORY_CPU,
				Payload: &pb.Event_Cpu{Cpu: &pb.CpuSample{UsagePct: float64(i)}}})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Emit blocked while writer stalled")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadUint64(&s.dropped) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if atomic.LoadUint64(&s.dropped) == 0 {
		t.Fatal("expected drops while writer blocked, got 0")
	}

	close(bw.release) // unblock so Close can drain and return
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}
