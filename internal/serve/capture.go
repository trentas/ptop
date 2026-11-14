package serve

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/trentas/ptop/internal/report"
	"github.com/trentas/ptop/pkg/collector"
	pb "github.com/trentas/ptop/pkg/streampb"
)

// CaptureOptions tunes a Capture (#156).
type CaptureOptions struct {
	// For is how long the window runs once every probe has attached.
	For time.Duration
	// TopN and ListCap go to the report; see report.Config.
	TopN, ListCap int
	// JSONLPath, if set, also writes the window's raw events there, as --serve
	// --export does: the report is the digest, this is what it was made from.
	JSONLPath string
	// Build identifies this ptop in the report's handshake (#145).
	Build PtopBuild
	// Exited closes when the target is gone, which ends the window early. nil
	// never closes; see WatchPID.
	Exited <-chan struct{}
	// Started, if set, is closed when the window opens: after the events
	// start reaching the report, and before the window's clock runs.
	Started chan<- struct{}
}

// Capture runs one fixed window over the target feed is watching and returns
// its report (#156). The window opens once Capture is running, so the caller
// starts the feed (and with it every probe) first: attaching takes a second or
// two, and that time is not part of the window.
//
// The report is built from the events the stream would carry, through the same
// Hub that maps them for a subscriber, so a report and a stream of one capture
// agree. It ends when opts.For runs out, when ctx is cancelled (INTERRUPTED), or
// when opts.Exited closes (TARGET_EXITED). Either way the report covers what
// was observed.
func Capture(ctx context.Context, target Target, feed *collector.Feed, resolver StackResolver, opts CaptureOptions) (*pb.CaptureReport, error) {
	if feed == nil {
		return nil, errors.New("serve: Capture needs a running feed")
	}
	if opts.For <= 0 {
		return nil, fmt.Errorf("serve: capture window of %v", opts.For)
	}

	buildID := ""
	if resolver != nil {
		buildID = resolver.ProcessBuildID()
	}
	hub := NewHub(target, buildID, feed.Set)
	hub.build = opts.Build.wire()
	hub.targetBuild = readTargetBuild(target)

	b := report.New(report.Config{TopN: opts.TopN, ListCap: opts.ListCap})
	hub.AddSink(b)
	if opts.JSONLPath != "" {
		js, err := newJSONLSink(opts.JSONLPath, hub.targetInfo())
		if err != nil {
			return nil, fmt.Errorf("serve: jsonl export: %w", err)
		}
		hub.AddSink(js)
		defer func() { hub.RemoveSink(js); _ = js.Close() }()
		fmt.Fprintf(os.Stderr, "[ptop] also exporting events to %s\n", opts.JSONLPath)
	}

	// The probe set as the window opens. A probe that changes state during it
	// is in the report's probe_changes, in order with what it explains.
	info := hub.targetInfo()

	hubCtx, detach := context.WithCancel(ctx)
	defer detach()
	hub.Start(hubCtx, feed.Bus)
	start := time.Now()
	hub.reportProbes()
	fmt.Fprintf(os.Stderr, "[ptop] capturing %s for %v\n", target, opts.For)
	if opts.Started != nil {
		close(opts.Started)
	}

	how := pb.WindowEnd_WINDOW_END_COMPLETE
	timer := time.NewTimer(opts.For)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		how = pb.WindowEnd_WINDOW_END_INTERRUPTED
	case <-opts.Exited:
		how = pb.WindowEnd_WINDOW_END_TARGET_EXITED
	}
	end := time.Now()
	hub.RemoveSink(b)

	return b.Report(info, report.Window{Start: start, End: end, Requested: opts.For, How: how}), nil
}

// watchInterval is how often WatchPID looks. An exit is reported up to this
// late, which is what the report's duration then over-counts by.
const watchInterval = 100 * time.Millisecond

// WatchPID returns a channel closed once pid is gone: no such process, or a
// zombie, which has exited and only waits for its parent to reap it. It stops
// looking when ctx is cancelled.
func WatchPID(ctx context.Context, pid int) <-chan struct{} {
	gone := make(chan struct{})
	go func() {
		t := time.NewTicker(watchInterval)
		defer t.Stop()
		for {
			if pidGone(pid) {
				close(gone)
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	return gone
}

func pidGone(pid int) bool {
	if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
		return true
	}
	// A zombie still answers kill(0). On Linux its state says it exited; where
	// there is no /proc, the read fails and the answer is kill's.
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	// The state follows the command name, which is in parentheses and may
	// itself contain them: read it after the last one.
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		return false
	}
	state := s[i+2]
	return state == 'Z' || state == 'X'
}
