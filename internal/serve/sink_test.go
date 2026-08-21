package serve

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/trentas/ptop/pkg/streampb"
)

// jsonlSink opens with a target header, then writes one parseable protojson
// Event per line, and Close flushes what's queued.
func TestJSONLSinkRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	s, err := newJSONLSink(path, &pb.TargetInfo{
		Mode: pb.TargetMode_TARGET_MODE_PID,
		Pid:  7,
	})
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

	sc := bufio.NewScanner(f)

	// Line 1 is the header, not an event.
	if !sc.Scan() {
		t.Fatal("empty export: no target header")
	}
	var meta pb.StreamMeta
	if err := protojson.Unmarshal(sc.Bytes(), &meta); err != nil {
		t.Fatalf("first line is not a StreamMeta: %v", err)
	}
	if meta.GetTarget().GetPid() != 7 || meta.GetTarget().GetMode() != pb.TargetMode_TARGET_MODE_PID {
		t.Errorf("header target = %v, want pid mode for pid 7", meta.GetTarget())
	}

	var lines int
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
		t.Errorf("got %d event lines, want %d", lines, n)
	}
}

// A cgroup-mode export must be attributable: the events carry no pid at all, so
// the header is the only thing that says what was observed.
func TestJSONLSinkHeaderCarriesCgroupTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	const cg = "/sys/fs/cgroup/kubepods.slice/pod.slice/ctr.scope"
	s, err := newJSONLSink(path, &pb.TargetInfo{
		Mode:       pb.TargetMode_TARGET_MODE_CGROUP,
		CgroupPath: cg,
		CgroupId:   23156,
	})
	if err != nil {
		t.Fatalf("newJSONLSink: %v", err)
	}
	s.Emit(&pb.Event{Category: pb.Category_CATEGORY_CPU,
		Payload: &pb.Event_Cpu{Cpu: &pb.CpuSample{UsagePct: 1}}})
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	first := strings.SplitN(string(b), "\n", 2)[0]
	var meta pb.StreamMeta
	if err := protojson.Unmarshal([]byte(first), &meta); err != nil {
		t.Fatalf("first line is not a StreamMeta: %v", err)
	}
	ti := meta.GetTarget()
	if ti.GetMode() != pb.TargetMode_TARGET_MODE_CGROUP {
		t.Errorf("mode = %v, want CGROUP", ti.GetMode())
	}
	if ti.GetCgroupPath() != cg || ti.GetCgroupId() != 23156 {
		t.Errorf("header target = %v, want %s (id 23156)", ti, cg)
	}
}

// Header write failures surface at construction: better to refuse than to leave
// an export nobody can attribute.
func TestJSONLSinkHeaderWriteFailure(t *testing.T) {
	_, err := newJSONLSinkWriter(failingWriter{}, &pb.TargetInfo{Pid: 1})
	if err == nil {
		t.Fatal("newJSONLSinkWriter = nil error, want the header failure")
	}
	if !strings.Contains(err.Error(), "target header") {
		t.Errorf("error = %q, want it to name the header", err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk gone") }
func (failingWriter) Close() error              { return nil }

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
	// No header here: it is written synchronously, so it would block in the
	// constructor on this deliberately stalled writer.
	s, err := newJSONLSinkWriter(bw, nil)
	if err != nil {
		t.Fatalf("newJSONLSinkWriter: %v", err)
	}

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
