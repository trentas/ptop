package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/trentas/ptop/pkg/collector"
)

// TestProcessStateSumsUpTheThreads pins the header badge to the target's
// threads. It used to be the mockup's RUNNING, set once and never updated.
func TestProcessStateSumsUpTheThreads(t *testing.T) {
	th := func(states ...string) []collector.ThreadInfo {
		out := make([]collector.ThreadInfo, len(states))
		for i, s := range states {
			out[i] = collector.ThreadInfo{TID: i + 1, State: s}
		}
		return out
	}
	cases := []struct {
		name    string
		threads []collector.ThreadInfo
		want    string
	}{
		{"no thread sample: no badge", nil, ""},
		{"a parked main thread beside a busy worker", th("sleeping", "running", "sleeping"), "RUNNING"},
		{"one thread in D and none running", th("sleeping", "blocked"), "BLOCKED"},
		{"all stopped", th("stopped", "stopped"), "STOPPED"},
		{"idle", th("sleeping", "sleeping"), "SLEEPING"},
		{"one stopped among sleepers", th("stopped", "sleeping"), "SLEEPING"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := processState(tc.threads); got != tc.want {
				t.Fatalf("processState = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFmtUptime(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{-time.Second, "00:00"},
		{75 * time.Second, "01:15"},
		{time.Hour + 2*time.Minute + 3*time.Second, "1:02:03"},
		{40*24*time.Hour + 5*time.Hour + 6*time.Minute, "40d 05:06"},
	}
	for _, tc := range cases {
		if got := fmtUptime(tc.d); got != tc.want {
			t.Errorf("fmtUptime(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

// TestHeaderShowsTheTargetsStateAndUptime checks the header against the
// target, and that a missing reading leaves its segment out rather than
// showing ptop's own session time or a fixed RUNNING.
func TestHeaderShowsTheTargetsStateAndUptime(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.Width, m.Height = 200, 40

	bare := ansiRe.ReplaceAllString(renderHeader(m), "")
	for _, absent := range []string{"RUNNING", "uptime"} {
		if strings.Contains(bare, absent) {
			t.Errorf("header with nothing read shows %q:\n%s", absent, bare)
		}
	}

	m.Threads = []collector.ThreadInfo{{TID: 1, State: "sleeping"}, {TID: 2, State: "sleeping"}}
	m.ProcCtx.StartTime = time.Now().Add(-(3*24*time.Hour + 4*time.Hour + 5*time.Minute))
	full := ansiRe.ReplaceAllString(renderHeader(m), "")
	for _, want := range []string{"SLEEPING", "uptime 3d 04:05"} {
		if !strings.Contains(full, want) {
			t.Errorf("header missing %q:\n%s", want, full)
		}
	}
}

// TestHeaderWithEverySegmentFitsWidth is TestChromeFitsWidth with the state
// badge, the runtime, a container id and a days-long uptime all present.
func TestHeaderWithEverySegmentFitsWidth(t *testing.T) {
	for _, w := range []int{60, 80, 100, 110, 120, 140, 200} {
		m := NewModel(Config{PID: 4194304, FPS: 5, NoEBPF: true})
		m.Width, m.Height = w, 40
		m.ProcessName = "some-long-process-name"
		m.Runtime = "Go 1.25"
		m.ProcCtx.Container = "0123456789ab"
		m.ProcCtx.StartTime = time.Now().Add(-400 * 24 * time.Hour)
		m.Threads = []collector.ThreadInfo{{TID: 1, State: "blocked"}}
		if vw := visibleWidth(renderHeader(m)); vw > w {
			t.Errorf("w=%d header overflow: visible=%d", w, vw)
		}
	}
}
