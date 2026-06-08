package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/trentas/ptop/pkg/collector"
)

// TestTLSPayloadMsgCappedNewestFirst confirms TLS payloads are retained
// newest-first and bounded, and flow into the snapshot export (the only place
// they surface — there is no live panel).
func TestTLSPayloadMsgCappedNewestFirst(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	for i := 0; i < 60; i++ {
		nm, _ := m.Update(TLSPayloadMsg(collector.TLSPayload{
			Timestamp: time.Now(), Dir: "write", FD: i, Len: 10,
		}))
		m = nm.(Model)
	}
	if len(m.TLSPayloads) != 40 {
		t.Errorf("TLSPayloads len = %d, want cap 40", len(m.TLSPayloads))
	}
	if m.TLSPayloads[0].FD != 59 {
		t.Errorf("head FD = %d, want 59 (newest-first)", m.TLSPayloads[0].FD)
	}
	snap := buildSnapshot(m)
	if len(snap.Data.TLSPayloads) != 40 {
		t.Errorf("snapshot TLSPayloads len = %d, want 40", len(snap.Data.TLSPayloads))
	}
}

// TestTLSHelpRows confirms the help overlay is honest about the TLS source:
// "off" + the enable hint when not requested, and "libssl" when attached.
func TestTLSHelpRows(t *testing.T) {
	off := Model{Width: 120, Height: 44}
	if out := renderHelpOverlayWithStatus(off, 120, 44); !strings.Contains(out, "enable with --tls") {
		t.Errorf("help (TLS off) missing the --tls enable hint")
	}

	on := Model{Width: 120, Height: 44, tlsSource: "eBPF"}
	on.cfg.TLS = true
	if out := renderHelpOverlayWithStatus(on, 120, 44); !strings.Contains(out, "libssl") {
		t.Errorf("help (TLS attached) missing the libssl source label")
	}
}
