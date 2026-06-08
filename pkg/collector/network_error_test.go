package collector

import (
	"testing"
	"time"
)

func TestNetErrKind(t *testing.T) {
	cases := map[uint32]string{
		netErrKindRefused:    "refused",
		netErrKindReset:      "reset",
		netErrKindRetransmit: "retransmit",
		99:                   "?",
	}
	for code, want := range cases {
		if got := netErrKind(code); got != want {
			t.Errorf("netErrKind(%d) = %q, want %q", code, got, want)
		}
	}
}

func TestFormatRemote(t *testing.T) {
	tests := []struct {
		name   string
		addr   [16]byte
		port   uint16
		family uint16
		want   string
	}{
		{
			name:   "ipv4",
			addr:   [16]byte{10, 0, 1, 5},
			port:   5432,
			family: 2,
			want:   "10.0.1.5:5432",
		},
		{
			name:   "ipv6 loopback",
			addr:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			port:   443,
			family: 10,
			want:   "[::1]:443",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatRemote(tt.addr, tt.port, tt.family); got != tt.want {
				t.Errorf("formatRemote = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecodeNetError(t *testing.T) {
	ts := time.Unix(1700000000, 0)
	daddr := [16]byte{10, 0, 1, 5}

	t.Run("refused carries latency-to-RST", func(t *testing.T) {
		ne := decodeNetError(ts, daddr, 5432, 2, netErrKindRefused, 0, 1_500_000)
		if ne.Kind != "refused" {
			t.Errorf("Kind = %q, want refused", ne.Kind)
		}
		if ne.Remote != "10.0.1.5:5432" {
			t.Errorf("Remote = %q", ne.Remote)
		}
		if ne.DetailMs != 1.5 {
			t.Errorf("DetailMs = %v, want 1.5", ne.DetailMs)
		}
		if !ne.Timestamp.Equal(ts) {
			t.Errorf("Timestamp = %v, want %v", ne.Timestamp, ts)
		}
	})

	t.Run("reset distinguished from refused", func(t *testing.T) {
		ne := decodeNetError(ts, daddr, 443, 2, netErrKindReset, 3, 42_000_000)
		if ne.Kind != "reset" {
			t.Errorf("Kind = %q, want reset", ne.Kind)
		}
		if ne.Retransmits != 3 {
			t.Errorf("Retransmits = %d, want 3", ne.Retransmits)
		}
		if ne.DetailMs != 42 {
			t.Errorf("DetailMs = %v, want 42", ne.DetailMs)
		}
	})

	t.Run("retransmit carries running count, zero detail", func(t *testing.T) {
		ne := decodeNetError(ts, daddr, 5432, 2, netErrKindRetransmit, 7, 0)
		if ne.Kind != "retransmit" {
			t.Errorf("Kind = %q, want retransmit", ne.Kind)
		}
		if ne.Retransmits != 7 {
			t.Errorf("Retransmits = %d, want 7", ne.Retransmits)
		}
		if ne.DetailMs != 0 {
			t.Errorf("DetailMs = %v, want 0", ne.DetailMs)
		}
	})
}
