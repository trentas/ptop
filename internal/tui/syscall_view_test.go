package tui

import (
	"strings"
	"testing"

	"github.com/trentas/ptop/pkg/collector"
)

// TestSyscallsMsgCarriesLatencyToF2 checks that a real snapshot reaches F2 with
// its mean latency, and that a syscall nobody timed shows "—" rather than a
// latency of zero (#139).
func TestSyscallsMsgCarriesLatencyToF2(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	nm, _ := m.Update(SyscallsMsg([]collector.SyscallEvent{
		{Name: "epoll_pwait", Count: 4, LatencyNs: 4 * 50_000_000},
		{Name: "getpid", Count: 10, LatencyNs: 10 * 850},
	}))
	mm := nm.(Model)
	if mm.usingMockSyscalls {
		t.Error("a real snapshot should clear usingMockSyscalls")
	}
	if mm.SyscallCounts["epoll_pwait"] != 4 || mm.SyscallLatNs["epoll_pwait"] != 200_000_000 {
		t.Fatalf("snapshot not recorded: counts=%v lat=%v", mm.SyscallCounts, mm.SyscallLatNs)
	}

	out := renderSyscallTable(mm.SyscallCounts, mm.SyscallLatNs, 100, 20)
	for _, want := range []string{"AVG", "epoll_pwait", "50.0ms", "getpid", "850ns"} {
		if !strings.Contains(out, want) {
			t.Errorf("F2 table missing %q:\n%s", want, out)
		}
	}

	// Counts with no latency — the simulated feed — must not read as 0ns.
	untimed := renderSyscallTable(map[string]uint64{"read": 3}, map[string]uint64{}, 100, 20)
	if strings.Contains(untimed, "0ns") || !strings.Contains(untimed, "—") {
		t.Errorf("an untimed syscall should show —, not a zero latency:\n%s", untimed)
	}
}

func TestFmtNs(t *testing.T) {
	cases := map[float64]string{
		850:         "850ns",
		12_400:      "12.4µs",
		3_500_000:   "3.5ms",
		2e9:         "2.00s",
		233_847_000: "233.8ms",
	}
	for in, want := range cases {
		if got := fmtNs(in); got != want {
			t.Errorf("fmtNs(%v) = %q, want %q", in, got, want)
		}
	}
}
