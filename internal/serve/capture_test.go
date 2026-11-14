package serve

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/trentas/ptop/pkg/collector"
	pb "github.com/trentas/ptop/pkg/streampb"
)

// captureRun runs Capture over one fake collector in the background and hands
// the test the collector once the window is open.
type captureRun struct {
	f    *fakeCollector
	done chan struct{}
	r    *pb.CaptureReport
	err  error
}

func startCapture(t *testing.T, ctx context.Context, opts CaptureOptions) *captureRun {
	t.Helper()
	busCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	run := &captureRun{f: newFake(8), done: make(chan struct{})}
	feed := &collector.Feed{Bus: collector.StartBus(busCtx, []collector.Collector{run.f})}
	started := make(chan struct{})
	opts.Started = started
	go func() {
		defer close(run.done)
		run.r, run.err = Capture(ctx, TargetPID(os.Getpid()), feed, nil, opts)
	}()
	select {
	case <-started:
	case <-run.done:
		t.Fatalf("Capture returned before the window opened: %v", run.err)
	case <-time.After(5 * time.Second):
		t.Fatal("the window never opened")
	}
	return run
}

func (c *captureRun) wait(t *testing.T) *pb.CaptureReport {
	t.Helper()
	select {
	case <-c.done:
	case <-time.After(10 * time.Second):
		t.Fatal("Capture did not return")
	}
	if c.err != nil {
		t.Fatalf("Capture: %v", c.err)
	}
	return c.r
}

func syscalls(read uint64) []collector.SyscallEvent {
	return []collector.SyscallEvent{{Name: "read", Count: read, LatencyNs: read * 10}}
}

// A window that runs its course reports what the stream carried during it, as
// the difference from its first reading.
func TestCaptureCompleteWindow(t *testing.T) {
	const window = 400 * time.Millisecond
	run := startCapture(t, context.Background(), CaptureOptions{For: window, TopN: 5})
	run.f.ch <- syscalls(10)
	run.f.ch <- syscalls(25)
	r := run.wait(t)

	w := r.GetWindow()
	if w.GetEnd() != pb.WindowEnd_WINDOW_END_COMPLETE {
		t.Errorf("end = %v, want COMPLETE", w.GetEnd())
	}
	if w.GetRequestedMs() != uint64(window.Milliseconds()) || w.GetDurationMs() < w.GetRequestedMs() {
		t.Errorf("requested %dms, ran %dms: want %d, and at least that", w.GetRequestedMs(), w.GetDurationMs(), window.Milliseconds())
	}
	if w.GetTopN() != 5 {
		t.Errorf("top_n = %d, want 5", w.GetTopN())
	}
	if got := r.GetSyscalls().GetCount(); got != 15 {
		t.Errorf("syscalls = %d, want 15 (25 - 10)", got)
	}
	if r.GetTarget().GetPid() != int32(os.Getpid()) {
		t.Errorf("target pid = %d, want %d", r.GetTarget().GetPid(), os.Getpid())
	}
}

// SIGINT ends the window early, and the report still covers what it saw.
func TestCaptureInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	run := startCapture(t, ctx, CaptureOptions{For: time.Minute})
	run.f.ch <- syscalls(1)
	run.f.ch <- syscalls(4)
	time.Sleep(100 * time.Millisecond) // let the bus deliver both
	cancel()
	r := run.wait(t)

	if r.GetWindow().GetEnd() != pb.WindowEnd_WINDOW_END_INTERRUPTED {
		t.Errorf("end = %v, want INTERRUPTED", r.GetWindow().GetEnd())
	}
	if d := r.GetWindow().GetDurationMs(); d >= uint64(time.Minute.Milliseconds()) {
		t.Errorf("duration = %dms, want the time it actually ran", d)
	}
	if got := r.GetSyscalls().GetCount(); got != 3 {
		t.Errorf("syscalls = %d, want 3", got)
	}
}

// A target that exits ends the window, and the report says so.
func TestCaptureTargetExited(t *testing.T) {
	exited := make(chan struct{})
	run := startCapture(t, context.Background(), CaptureOptions{For: time.Minute, Exited: exited})
	run.f.ch <- syscalls(7)
	close(exited)
	r := run.wait(t)

	if r.GetWindow().GetEnd() != pb.WindowEnd_WINDOW_END_TARGET_EXITED {
		t.Errorf("end = %v, want TARGET_EXITED", r.GetWindow().GetEnd())
	}
	if d := r.GetWindow().GetDurationMs(); d >= uint64(time.Minute.Milliseconds()) {
		t.Errorf("duration = %dms, want the time it actually ran", d)
	}
}

// --export beside --for writes the window's raw events, with the handshake as
// the first line, as --serve --export does.
func TestCaptureAlsoExportsTheEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	run := startCapture(t, context.Background(), CaptureOptions{For: 300 * time.Millisecond, JSONLPath: path})
	run.f.ch <- syscalls(1)
	run.f.ch <- syscalls(2)
	run.wait(t)

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines []*pb.SubscribeResponse
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var resp pb.SubscribeResponse
		if err := protojson.Unmarshal(sc.Bytes(), &resp); err != nil {
			t.Fatalf("line %d: %v", len(lines)+1, err)
		}
		lines = append(lines, &resp)
	}
	if len(lines) != 3 {
		t.Fatalf("%d lines, want the handshake and two events", len(lines))
	}
	if lines[0].GetMeta().GetTarget() == nil {
		t.Errorf("line 1 = %v, want the TargetInfo handshake", lines[0])
	}
	for i, l := range lines[1:] {
		if l.GetEvent().GetSyscalls() == nil {
			t.Errorf("line %d = %v, want a syscall snapshot", i+2, l)
		}
	}
}

func TestCaptureRefusesAnEmptyWindow(t *testing.T) {
	feed := &collector.Feed{Bus: collector.StartBus(context.Background(), nil)}
	if _, err := Capture(context.Background(), TargetPID(1), feed, nil, CaptureOptions{}); err == nil {
		t.Error("Capture with no window = nil error")
	}
	if _, err := Capture(context.Background(), TargetPID(1), nil, nil, CaptureOptions{For: time.Second}); err == nil {
		t.Error("Capture with no feed = nil error")
	}
}

func TestWatchPIDSeesAReapedProcess(t *testing.T) {
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-WatchPID(context.Background(), cmd.Process.Pid):
	case <-time.After(2 * time.Second):
		t.Fatal("WatchPID did not report a process that is gone")
	}
}

// A process that has exited and not yet been reaped is gone: it runs nothing.
// Only Linux says so through /proc; elsewhere it is gone once its parent reaps
// it, which a shell does at once.
func TestWatchPIDSeesAZombie(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("a zombie is told apart through /proc/<pid>/stat")
	}
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Wait() })
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-WatchPID(context.Background(), cmd.Process.Pid):
	case <-time.After(2 * time.Second):
		t.Fatal("WatchPID did not report a zombie")
	}
}

func TestWatchPIDLeavesALiveProcessAlone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	select {
	case <-WatchPID(ctx, os.Getpid()):
		t.Fatal("WatchPID reported this process gone")
	case <-time.After(3 * watchInterval):
	}
}
