package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/trentas/ptop/pkg/collector"
)

// TestNetErrorMsgUpdatesState verifies a NetErrorMsg lands in the model
// (newest-first), is mirrored into the net timeline feed, marks the network
// source as real, and that F3 then renders the anomaly in the Anomalies panel.
func TestNetErrorMsgUpdatesState(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	ne := collector.NetError{
		Timestamp: time.Now(),
		Kind:      "refused",
		Remote:    "10.0.1.5:5432",
		DetailMs:  1.5,
	}
	nm, _ := m.Update(NetErrorMsg(ne))
	mm := nm.(Model)

	if len(mm.NetErrors) != 1 || mm.NetErrors[0].Remote != ne.Remote {
		t.Fatalf("NetErrors not recorded: %+v", mm.NetErrors)
	}
	if mm.usingMockNet {
		t.Errorf("a real net error should clear usingMockNet")
	}
	// The error is mirrored into the timeline under the "net" category.
	netTL := filterTimelineByCategory(mm.Timeline, "net")
	if len(netTL) == 0 || !strings.Contains(netTL[0].Message, "refused") {
		t.Errorf("net error not synthesized into the timeline: %+v", netTL)
	}

	mm.Width, mm.Height = 180, 50
	mm.ActiveTab = TabNetwork
	out := mm.View()
	for _, want := range []string{"ANOMALIES", "refused", "10.0.1.5:5432"} {
		if !strings.Contains(out, want) {
			t.Errorf("F3 network view missing %q with a net error present", want)
		}
	}
}

// TestNetErrorsNewestFirstCapped confirms the panel keeps the most recent
// errors first and bounds the retained list.
func TestNetErrorsNewestFirstCapped(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	for i := 0; i < 60; i++ {
		nm, _ := m.Update(NetErrorMsg(collector.NetError{
			Timestamp:   time.Now(),
			Kind:        "retransmit",
			Remote:      "1.2.3.4:443",
			Retransmits: uint32(i),
		}))
		m = nm.(Model)
	}
	mm := m
	if len(mm.NetErrors) != 40 {
		t.Errorf("NetErrors len = %d, want cap 40", len(mm.NetErrors))
	}
	// Newest-first: the last appended (Retransmits=59) is at the head.
	if mm.NetErrors[0].Retransmits != 59 {
		t.Errorf("head Retransmits = %d, want 59 (newest-first)", mm.NetErrors[0].Retransmits)
	}
}

// TestNetErrorMessage covers the one-line rendering per error kind.
func TestNetErrorMessage(t *testing.T) {
	cases := []struct {
		name string
		e    collector.NetError
		want string
	}{
		{"refused with timing", collector.NetError{Kind: "refused", Remote: "10.0.1.5:5432", DetailMs: 1.5},
			"refused → 10.0.1.5:5432 (RST 1.5ms)"},
		{"refused no timing", collector.NetError{Kind: "refused", Remote: "10.0.1.5:5432"},
			"refused → 10.0.1.5:5432"},
		{"reset mid-stream", collector.NetError{Kind: "reset", Remote: "1.2.3.4:443", DetailMs: 42},
			"reset → 1.2.3.4:443 mid-stream (42.0ms)"},
		{"retransmit count", collector.NetError{Kind: "retransmit", Remote: "1.2.3.4:443", Retransmits: 7},
			"retransmit ×7 → 1.2.3.4:443"},
		{"unknown kind", collector.NetError{Kind: "weird", Remote: "h:1"}, "weird → h:1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := netErrorMessage(c.e); got != c.want {
				t.Errorf("netErrorMessage = %q, want %q", got, c.want)
			}
		})
	}
}

// TestNetAnomaliesHonestSource confirms the panel never invents anomalies:
// a real (non-mock) source with no errors reads healthy; a mock source says
// the capability needs eBPF.
func TestNetAnomaliesHonestSource(t *testing.T) {
	real := Model{usingMockNet: false}
	if got := renderNetAnomalies(real, 40, 5); !strings.Contains(got, "no network errors") {
		t.Errorf("real source, no errors = %q, want healthy", got)
	}
	mock := Model{usingMockNet: true}
	if got := renderNetAnomalies(mock, 40, 5); !strings.Contains(got, "eBPF") {
		t.Errorf("mock source = %q, want eBPF hint", got)
	}
}
