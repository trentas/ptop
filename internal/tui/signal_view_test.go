package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/trentas/ptop/pkg/collector"
)

// TestSignalMsgUpdatesState verifies a SignalMsg lands in the model
// (newest-first), is mirrored into the unified timeline under the "sig"
// category, and that F7 then renders the SIG badge + the sender attribution.
func TestSignalMsgUpdatesState(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	se := collector.SignalEvent{
		Timestamp:  time.Now(),
		Signal:     "SIGTERM",
		Signo:      15,
		SenderPID:  4242,
		SenderComm: "bash",
		TargetTID:  99,
	}
	nm, _ := m.Update(SignalMsg(se))
	mm := nm.(Model)

	if len(mm.Signals) != 1 || mm.Signals[0].SenderPID != se.SenderPID {
		t.Fatalf("Signals not recorded: %+v", mm.Signals)
	}
	sigTL := filterTimelineByCategory(mm.Timeline, "sig")
	if len(sigTL) == 0 || !strings.Contains(sigTL[0].Message, "SIGTERM") {
		t.Errorf("signal not synthesized into the timeline: %+v", sigTL)
	}

	mm.Width, mm.Height = 180, 50
	mm.ActiveTab = TabTimeline
	out := mm.View()
	for _, want := range []string{"SIG", "SIGTERM", "bash"} {
		if !strings.Contains(out, want) {
			t.Errorf("F7 timeline missing %q with a signal present", want)
		}
	}
}

// TestSignalsNewestFirstCapped confirms the list keeps the most recent signals
// first and bounds the retained slice.
func TestSignalsNewestFirstCapped(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	for i := 0; i < 60; i++ {
		nm, _ := m.Update(SignalMsg(collector.SignalEvent{
			Timestamp: time.Now(),
			Signal:    "SIGUSR1",
			Signo:     10,
			SenderPID: int32(i), // tag for ordering assertion
		}))
		m = nm.(Model)
	}
	mm := m
	if len(mm.Signals) != 40 {
		t.Errorf("Signals len = %d, want cap 40", len(mm.Signals))
	}
	if mm.Signals[0].SenderPID != 59 {
		t.Errorf("head SenderPID = %d, want 59 (newest-first)", mm.Signals[0].SenderPID)
	}
}

// TestSignalMessage covers the one-line rendering: process-sent vs kernel.
func TestSignalMessage(t *testing.T) {
	cases := []struct {
		name string
		e    collector.SignalEvent
		want string
	}{
		{"external with comm", collector.SignalEvent{Signal: "SIGTERM", SenderPID: 4242, SenderComm: "bash"},
			"SIGTERM ← pid 4242 (bash)"},
		{"external no comm", collector.SignalEvent{Signal: "SIGINT", SenderPID: 7},
			"SIGINT ← pid 7"},
		{"kernel-generated", collector.SignalEvent{Signal: "SIGSEGV", SenderPID: 100, SenderComm: "x", Code: siCodeKernel},
			"SIGSEGV (kernel)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := signalMessage(c.e); got != c.want {
				t.Errorf("signalMessage = %q, want %q", got, c.want)
			}
		})
	}
}
