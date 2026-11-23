package tui

import (
	"strings"
	"testing"

	"github.com/trentas/ptop/pkg/collector"
)

func openFDs(n int) []collector.FDEntry {
	fds := make([]collector.FDEntry, n)
	for i := range fds {
		fds[i] = collector.FDEntry{FD: i, Type: "socket", Desc: "TCP 10.0.0.1:443"}
	}
	return fds
}

// TestFDAlertComparesWithTheLimit pins the F6 alert to the target's own soft
// RLIMIT_NOFILE. It used to fire above a fixed 20, so a process with 28 fds and
// a limit of 524288 read "close to the limit".
func TestFDAlertComparesWithTheLimit(t *testing.T) {
	cases := []struct {
		name  string
		open  int
		limit *collector.FDLimit
		want  string // substring of the alert; "" means no limit alert
	}{
		{"the reported case", 28, &collector.FDLimit{Soft: 524288, Hard: 524288}, ""},
		{"below the threshold", 819, &collector.FDLimit{Soft: 1024, Hard: 524288}, ""},
		{"at the threshold", 820, &collector.FDLimit{Soft: 1024, Hard: 524288}, "820/1024 fds open — 80% of limit"},
		{"at the limit", 1024, &collector.FDLimit{Soft: 1024, Hard: 524288}, "1024/1024 fds open — 100% of limit"},
		{"unlimited", 5000, &collector.FDLimit{Soft: collector.FDLimitUnlimited, Hard: collector.FDLimitUnlimited}, ""},
		{"limit unknown", 5000, nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
			m.FDs = openFDs(tc.open)
			m.FDLimit = tc.limit
			out := renderFDAlerts(m)
			if tc.want == "" {
				if strings.Contains(out, "limit") {
					t.Fatalf("alert raised: %q", out)
				}
				return
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("alert %q, want it to contain %q", out, tc.want)
			}
		})
	}
}

// TestFDLimitReachesStats checks the limit travels from the bus to the Stats
// panel, and that an unknown one reads "—" rather than a number.
func TestFDLimitReachesStats(t *testing.T) {
	m := modelOnSet(t, procOnlySet())
	next, _ := m.Update(FDMsg(openFDs(28)))
	m = next.(Model)

	if got := renderFDStats(m, 40); !strings.Contains(got, "28 / —") {
		t.Errorf("Stats before any limit arrived:\n%s\nwant \"28 / —\"", got)
	}

	msg := busMsg(collector.FDLimit{Soft: 1024, Hard: 524288})
	if _, ok := msg.(FDLimitMsg); !ok {
		t.Fatalf("busMsg(FDLimit) = %T, want FDLimitMsg", msg)
	}
	next, _ = m.Update(msg)
	m = next.(Model)

	if m.FDLimit == nil || m.FDLimit.Soft != 1024 {
		t.Fatalf("model FDLimit = %+v, want soft 1024", m.FDLimit)
	}
	if got := renderFDStats(m, 40); !strings.Contains(got, "28 / 1024") {
		t.Errorf("Stats with a limit:\n%s\nwant \"28 / 1024\"", got)
	}
}
