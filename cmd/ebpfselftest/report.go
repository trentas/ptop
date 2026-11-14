//go:build linux && ebpf

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/trentas/ptop/internal/report"
	"github.com/trentas/ptop/internal/serve"
	"github.com/trentas/ptop/pkg/collector"
	pb "github.com/trentas/ptop/pkg/streampb"
)

// ─── report: a --for window over planted calls, digested (#156) ────────────
//
// The capture report is graded through serve.Capture, the code --for runs,
// against the collectors' real output: the unit tests in internal/report plant
// the readings, and this case plants the calls.
//
//   - getppid calls made once the probes are up but before the window opens
//     are the baseline's: a report that totals the last reading counts them.
//   - getppid calls and file writes made inside the window are counted exactly,
//     and the writes are credited to their file, to the byte.
//   - a probe switched off has no section, so its absence is not read as zero.
//   - a target that exits ends the window, which says so.

func checkReport(g *grader, pid int) {
	checkReportWindow(g, pid)
	checkReportTargetExit(g)
}

// onlySubsystems is the Disable map that leaves exactly keep running, as
// --probes builds it.
func onlySubsystems(keep ...string) map[string]bool {
	disable := make(map[string]bool)
	for _, name := range strings.Split(collector.KnownSubsystems(), ", ") {
		disable[name] = true
	}
	for _, name := range keep {
		delete(disable, name)
	}
	return disable
}

type captureResult struct {
	r   *pb.CaptureReport
	err error
}

func checkReportWindow(g *grader, pid int) {
	const (
		before = 3000 // getppid(2) once the probes are up, before the window opens
		inside = 7000 // getppid(2) inside the window
		writes = 50
		size   = 4096
		window = 4 * time.Second
	)
	dir, err := os.MkdirTemp("", "ptop-selftest-report-")
	if err != nil {
		g.broken("report", "temp dir", err)
		return
	}
	defer os.RemoveAll(dir)
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		g.broken("report", "temp dir", err)
		return
	}
	path := filepath.Join(dir, "planted")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	feed := collector.StartFeed(ctx, collector.SetConfig{
		PID:     pid,
		Disable: onlySubsystems(collector.SubsystemSyscalls, collector.SubsystemIO),
		ListCap: report.CollectorListCap,
	})
	defer feed.Stop()

	// The planted calls go in once each graded axis has taken its first
	// reading in the window, which is that axis's baseline: a call made between
	// the window opening and the reading is in neither end of the difference.
	// The axes tick apart (syscalls every second, io every 500ms), so waiting
	// for one is not waiting for the other.
	var (
		opened       atomic.Bool
		mu           sync.Mutex
		seenSys      bool
		seenIO       bool
		once         sync.Once
		firstReading = make(chan struct{})
	)
	h := feed.Bus.AddHandler(func(v any) {
		if !opened.Load() {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch v.(type) {
		case []collector.SyscallEvent:
			seenSys = true
		case collector.IOEBPFSnapshot:
			seenIO = true
		}
		if seenSys && seenIO {
			once.Do(func() { close(firstReading) })
		}
	})
	defer feed.Bus.RemoveHandler(h)

	for i := 0; i < before; i++ {
		_ = unix.Getppid()
	}

	started := make(chan struct{})
	res := make(chan captureResult, 1)
	go func() {
		// MaxTopN: the grade is on the counts, and a Go process makes enough
		// long-blocking syscalls to push a quick one out of a list of ten.
		r, err := serve.Capture(ctx, serve.TargetPID(pid), feed, nil, serve.CaptureOptions{
			For: window, TopN: report.MaxTopN, ListCap: report.CollectorListCap, Started: started,
		})
		res <- captureResult{r, err}
	}()
	select {
	case <-started:
	case x := <-res:
		g.broken("report", "open the window", x.err)
		return
	case <-time.After(10 * time.Second):
		g.broken("report", "open the window", errors.New("still not open after 10s"))
		return
	}
	opened.Store(true)
	select {
	case <-firstReading:
	case <-time.After(3 * time.Second):
		g.broken("report", "the window's first readings", errors.New("no syscall and io snapshots within 3s of the window opening"))
		return
	}

	for i := 0; i < inside; i++ {
		_ = unix.Getppid()
	}
	if err := plantFileWrites(path, writes, size); err != nil {
		g.broken("report", "write the planted file", err)
		return
	}

	var x captureResult
	select {
	case x = <-res:
	case <-time.After(window + 10*time.Second):
		g.broken("report", "close the window", errors.New("Capture did not return"))
		return
	}
	if x.err != nil {
		g.broken("report", "close the window", x.err)
		return
	}
	r := x.r

	w := r.GetWindow()
	g.check("report", "a window that ran its course says so", w.GetEnd() == pb.WindowEnd_WINDOW_END_COMPLETE,
		"COMPLETE", w.GetEnd().String())
	dur := time.Duration(w.GetDurationMs()) * time.Millisecond
	g.check("report", "the window's duration", dur >= window && dur < window+time.Second,
		fmt.Sprintf("[%v, %v)", window, window+time.Second), dur.String())

	var gp *pb.SyscallStat
	for _, s := range r.GetSyscalls().GetSyscalls() {
		if s.GetName() == "getppid" {
			gp = s
		}
	}
	if g.check("report", "getppid has a row", gp != nil, "a row",
		fmt.Sprintf("%d rows, %d syscalls in all", len(r.GetSyscalls().GetSyscalls()), r.GetSyscalls().GetTotalSyscalls())) {
		// before+inside is what a report reads without its baseline.
		g.check("report", fmt.Sprintf("getppid counts the window's calls, not the %d before it", before),
			gp.GetCount() == inside, fmt.Sprintf("exactly %d", inside), fmt.Sprint(gp.GetCount()))
		g.check("report", "getppid's latency is measured", gp.LatencyNs != nil && gp.GetLatencyNs() > 0,
			"present, > 0", fmt.Sprint(gp.GetLatencyNs()))
	}

	var row *pb.IoFile
	for _, f := range r.GetIo().GetFiles() {
		if f.GetPath() == path {
			row = f
		}
	}
	if g.check("report", "the planted file has a row", row != nil, path, ioPaths(r.GetIo())) {
		g.check("report", "its writes", row.GetWrites() == writes, fmt.Sprintf("exactly %d", writes), fmt.Sprint(row.GetWrites()))
		g.check("report", "its bytes", row.GetBytes() == writes*size, fmt.Sprintf("exactly %d", writes*size), fmt.Sprint(row.GetBytes()))
	}

	// Switched off, a section is absent; a probe that ran and counted nothing
	// would have one, with zeros in it.
	g.check("report", "heap was not asked for: no heap section", r.GetHeap() == nil, "absent", section(r.GetHeap() != nil))
	g.check("report", "signals was not asked for: no signals section", r.GetSignals() == nil, "absent", section(r.GetSignals() != nil))
	states := make(map[string]pb.ProbeState)
	for _, p := range r.GetTarget().GetProbes() {
		states[p.GetName()] = p.GetState()
	}
	g.check("report", "the probe set says which ran", states["syscalls"] == pb.ProbeState_PROBE_STATE_ACTIVE &&
		states["io"] == pb.ProbeState_PROBE_STATE_ACTIVE && states["heap"] == pb.ProbeState_PROBE_STATE_DISABLED,
		"syscalls and io active, heap disabled",
		fmt.Sprintf("syscalls %v, io %v, heap %v", states["syscalls"], states["io"], states["heap"]))
}

// checkReportTargetExit watches a child that exits a few seconds in, with a
// window far longer than that.
func checkReportTargetExit(g *grader) {
	const (
		lives  = 3 * time.Second
		window = 30 * time.Second
		// The window opens once the probe has attached, so it can only be
		// shorter than the child's life; WatchPID looks every 100ms.
		ceiling = lives + 500*time.Millisecond
	)
	child := exec.Command("sleep", fmt.Sprint(lives.Seconds()))
	if err := child.Start(); err != nil {
		g.broken("report", "start a child to watch", err)
		return
	}
	reaped := make(chan struct{})
	go func() { _ = child.Wait(); close(reaped) }()
	defer func() { _ = child.Process.Kill(); <-reaped }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cpid := child.Process.Pid
	feed := collector.StartFeed(ctx, collector.SetConfig{PID: cpid, Disable: onlySubsystems(collector.SubsystemCPU)})
	defer feed.Stop()

	res := make(chan captureResult, 1)
	go func() {
		r, err := serve.Capture(ctx, serve.TargetPID(cpid), feed, nil, serve.CaptureOptions{
			For: window, Exited: serve.WatchPID(ctx, cpid),
		})
		res <- captureResult{r, err}
	}()
	var x captureResult
	select {
	case x = <-res:
	case <-time.After(lives + 10*time.Second):
		g.broken("report", "a target that exits", errors.New("the window outlived its target by 10s"))
		return
	}
	if x.err != nil {
		g.broken("report", "a target that exits", x.err)
		return
	}
	w := x.r.GetWindow()
	g.check("report", "a target that exits ends the window", w.GetEnd() == pb.WindowEnd_WINDOW_END_TARGET_EXITED,
		"TARGET_EXITED", w.GetEnd().String())
	dur := time.Duration(w.GetDurationMs()) * time.Millisecond
	g.check("report", fmt.Sprintf("a window of %v over a target that lives %v", window, lives), dur < ceiling,
		fmt.Sprintf("< %v", ceiling), dur.String())
}

// plantFileWrites writes n blocks of size bytes to a new file, then closes it.
func plantFileWrites(path string, n, size int) error {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	buf := make([]byte, size)
	for i := 0; i < n; i++ {
		if k, err := unix.Write(fd, buf); err != nil || k != size {
			_ = unix.Close(fd)
			return fmt.Errorf("write %d: %d bytes, %v", i, k, err)
		}
	}
	return unix.Close(fd)
}

func ioPaths(r *pb.IoReport) string {
	if r == nil {
		return "no io section"
	}
	paths := make([]string, 0, len(r.GetFiles()))
	for _, f := range r.GetFiles() {
		paths = append(paths, f.GetPath())
	}
	return fmt.Sprintf("%d of %d files: %s", len(paths), r.GetTotalFiles(), strings.Join(paths, ", "))
}

func section(present bool) string {
	if present {
		return "present"
	}
	return "absent"
}
