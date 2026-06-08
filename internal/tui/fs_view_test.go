package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/trentas/ptop/pkg/collector"
)

// TestFSEventMsgUpdatesState verifies an FSEventMsg lands in the model
// (newest-first), is mirrored into the I/O timeline feed, marks the io-files
// source as real, and that F5 then renders a denial in the Anomalies panel.
func TestFSEventMsgUpdatesState(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	fe := collector.FSEvent{
		Timestamp: time.Now(),
		Op:        "denied",
		Path:      "/etc/shadow",
		Errno:     13,
		Err:       "EACCES",
	}
	nm, _ := m.Update(FSEventMsg(fe))
	mm := nm.(Model)

	if len(mm.FSEvents) != 1 || mm.FSEvents[0].Path != fe.Path {
		t.Fatalf("FSEvents not recorded: %+v", mm.FSEvents)
	}
	if mm.usingMockIOFiles {
		t.Errorf("a real fs event should clear usingMockIOFiles")
	}
	// The event is mirrored into the timeline under the "io" category.
	ioTL := filterTimelineByCategory(mm.Timeline, "io")
	if len(ioTL) == 0 || !strings.Contains(ioTL[0].Message, "denied") {
		t.Errorf("fs event not synthesized into the timeline: %+v", ioTL)
	}

	mm.Width, mm.Height = 180, 50
	mm.ActiveTab = TabIO
	out := mm.View()
	for _, want := range []string{"ANOMALIES", "denied", "/etc/shadow", "EACCES"} {
		if !strings.Contains(out, want) {
			t.Errorf("F5 I/O view missing %q with a denial present", want)
		}
	}
}

// TestFSEventsNewestFirstCapped confirms the list keeps the most recent events
// first and bounds the retained slice.
func TestFSEventsNewestFirstCapped(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	for i := 0; i < 60; i++ {
		op := "deleted"
		if i%2 == 0 {
			op = "denied"
		}
		nm, _ := m.Update(FSEventMsg(collector.FSEvent{
			Timestamp: time.Now(),
			Op:        op,
			Path:      "/tmp/f",
			Errno:     int32(i), // tag for ordering assertion
		}))
		m = nm.(Model)
	}
	mm := m
	if len(mm.FSEvents) != 40 {
		t.Errorf("FSEvents len = %d, want cap 40", len(mm.FSEvents))
	}
	if mm.FSEvents[0].Errno != 59 {
		t.Errorf("head Errno = %d, want 59 (newest-first)", mm.FSEvents[0].Errno)
	}
}

// TestFSEventMessage covers the one-line rendering per op.
func TestFSEventMessage(t *testing.T) {
	cases := []struct {
		name string
		e    collector.FSEvent
		want string
	}{
		{"denied", collector.FSEvent{Op: "denied", Path: "/etc/shadow", Errno: 13, Err: "EACCES"},
			"denied /etc/shadow (EACCES)"},
		{"deleted ok", collector.FSEvent{Op: "deleted", Path: "/tmp/cache.bin"},
			"deleted /tmp/cache.bin"},
		{"delete failed", collector.FSEvent{Op: "deleted", Path: "/tmp/busy", Errno: 16, Err: "EBUSY"},
			"delete failed /tmp/busy (EBUSY)"},
		{"renamed ok", collector.FSEvent{Op: "renamed", Path: "/data/a.tmp", NewPath: "/data/a.db"},
			"renamed /data/a.tmp → /data/a.db"},
		{"unknown op", collector.FSEvent{Op: "weird", Path: "/x"}, "weird /x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := fsEventMessage(c.e); got != c.want {
				t.Errorf("fsEventMessage = %q, want %q", got, c.want)
			}
		})
	}
}

// TestIOAnomaliesHonestSource confirms the panel never invents fs anomalies:
// a real (non-mock) io-files source with no denials reads healthy; only the
// mock source shows the simulated polling heuristic.
func TestIOAnomaliesHonestSource(t *testing.T) {
	real := Model{usingMockIOFiles: false}
	got := renderIOAnomalies(real, 40, 5)
	if !strings.Contains(got, "no permission denials") {
		t.Errorf("real source, no denials = %q, want healthy", got)
	}
	if strings.Contains(got, "polling") {
		t.Errorf("real source must not show the simulated polling line: %q", got)
	}
	mock := Model{usingMockIOFiles: true}
	if got := renderIOAnomalies(mock, 40, 5); !strings.Contains(got, "polling") {
		t.Errorf("mock source = %q, want the simulated polling line", got)
	}
}
