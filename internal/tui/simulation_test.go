package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/trentas/ptop/pkg/collector"
)

// modelOnSet builds a model over a Set whose populated fields say which
// subsystems have a real source. Nothing is started: the model consults only
// which fields are non-nil.
func modelOnSet(t *testing.T, set *collector.Set) Model {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	feed := &collector.Feed{Set: set, Bus: collector.StartBus(ctx, nil)}
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true, Feed: feed})
	next, _ := m.Update(tea.WindowSizeMsg{Width: 200, Height: 50})
	return next.(Model)
}

// demoModel is the model with nothing attached: every panel simulated.
func demoModel(t *testing.T) Model {
	t.Helper()
	return modelOnSet(t, &collector.Set{})
}

// procOnlySet is the --no-ebpf shape: the /proc collectors run, the eBPF axes
// (syscalls, io files, network, futex) have no source.
func procOnlySet() *collector.Set {
	return &collector.Set{
		FD:           &collector.FDCollector{},
		CPUProc:      &collector.CPUCollector{},
		ThreadsProc:  &collector.ThreadsCollector{},
		MemProc:      &collector.MemCollector{},
		IOWait:       &collector.IOWaitCollector{},
		IOThroughput: &collector.IOThroughputCollector{},
	}
}

// noEBPFProbes is what NewSet records under --no-ebpf, where the model reads
// a sourceless panel's reason from.
func noEBPFProbes() map[string]collector.ProbeStatus {
	return map[string]collector.ProbeStatus{
		collector.SubsystemCPU:      {Name: collector.SubsystemCPU, State: collector.ProbeActive, Source: collector.SourceProc},
		collector.SubsystemIO:       {Name: collector.SubsystemIO, State: collector.ProbeActive, Source: collector.SourceProc},
		collector.SubsystemNetwork:  {Name: collector.SubsystemNetwork, State: collector.ProbeDisabled, Detail: "--no-ebpf"},
		collector.SubsystemSyscalls: {Name: collector.SubsystemSyscalls, State: collector.ProbeFailed, Detail: "loading tracepoint: permission denied"},
		collector.SubsystemFutex:    {Name: collector.SubsystemFutex, State: collector.ProbeDisabled, Detail: "--no-ebpf"},
	}
}

// view renders one tab of m.
func view(m Model, tab int) string {
	m.ActiveTab = tab
	m.render.commit = true
	return m.View()
}

// simulatedMarkers are strings only the simulation produces: a panel showing
// one beside a real target is showing invented data.
var simulatedMarkers = []string{
	"/data/db", "/var/log/app", "10.0.1.5", "docker.sock", "mutex-A",
	"worker-1", "http-pool", "/tmp/cache", "polling (×12/s)",
}

// #149: beside a real target nothing is simulated — not seeded at startup,
// not added by the tick, not in any feed or panel.
func TestNothingSimulatedBesideARealTarget(t *testing.T) {
	m := modelOnSet(t, procOnlySet())
	m.probes = noEBPFProbes()
	for i := 0; i < 500; i++ {
		m.tick()
	}

	if len(m.Timeline) != 0 {
		t.Errorf("timeline holds %d events no collector published, first %q", len(m.Timeline), m.Timeline[0].Message)
	}
	if len(m.FDEvents) != 0 {
		t.Errorf("fd events hold %d events no collector published, first %q", len(m.FDEvents), m.FDEvents[0].Message)
	}
	for name, n := range map[string]int{
		"fds":           len(m.FDs),
		"cpu history":   len(m.CPUHistory),
		"threads":       len(m.Threads),
		"connections":   len(m.NetConns),
		"syscalls":      len(m.SyscallCounts),
		"top files":     len(m.IOStats.TopFiles),
		"latency":       len(m.IOStats.LatencyBuckets),
		"io read hist":  len(m.IOReadHist),
		"fd count hist": len(m.FDCountHistory),
	} {
		if n != 0 {
			t.Errorf("%s: %d entries no collector published", name, n)
		}
	}
	if m.MemStats != (collector.MemStats{}) {
		t.Errorf("memory holds %+v no collector published", m.MemStats)
	}
	if m.IOStats.Fsyncs != 0 || m.IOStats.Opens != 0 || m.IOStats.ReadOps != 0 {
		t.Errorf("io counters moved with no collector: %+v", m.IOStats)
	}

	for _, tab := range []int{TabOverview, TabSyscalls, TabNetwork, TabThreads, TabIO, TabFD, TabTimeline} {
		out := view(m, tab)
		for _, marker := range simulatedMarkers {
			if strings.Contains(out, marker) {
				t.Errorf("tab %d shows simulated %q beside a real target", tab+1, marker)
			}
		}
	}
}

// A panel with no source says so, with the reason its probe recorded.
func TestSourcelessPanelsSayWhy(t *testing.T) {
	m := modelOnSet(t, procOnlySet())
	m.probes = noEBPFProbes()

	// On macOS three of these have no source on any build, and say that
	// instead (#22).
	pick := func(unavailable bool, linux, macOS string) string {
		if unavailable {
			return macOS
		}
		return linux
	}
	cases := []struct {
		tab  int
		want string
	}{
		{TabOverview, "○ no source"},
		{TabOverview, "disabled: --no-ebpf"}, // Network panel
		{TabNetwork, "disabled: --no-ebpf"},
		{TabThreads, pick(locksUnavailable, "○ no source — disabled: --no-ebpf", "not available on macOS")},
		{TabSyscalls, pick(syscallsUnavailable, "failed to attach: loading tracepoint: permission denied", "not available on macOS")},
		{TabIO, pick(ioFilesUnavailable, "per-file I/O needs eBPF: disabled by --no-ebpf", "not available on macOS")},
	}
	for _, tc := range cases {
		if out := view(m, tc.tab); !strings.Contains(out, tc.want) {
			t.Errorf("tab %d: want it to say %q, got:\n%s", tc.tab+1, tc.want, out)
		}
	}

	// The overlay says the same, and calls nothing "mock".
	help := renderHelpOverlayWithStatus(m, 200, 200)
	if strings.Contains(help, "mock") {
		t.Errorf("overlay calls a subsystem mock beside a real target:\n%s", help)
	}
	if line := lineWith(help, "network"); !strings.Contains(line, "unavailable") || !strings.Contains(line, "--no-ebpf") {
		t.Errorf("overlay network row = %q, want unavailable with its reason", line)
	}
}

// The panels with a real source render normally, and the two IOStats
// counters no collector measures read as unmeasured, not 0.
func TestUnmeasuredFieldsReadAsUnmeasured(t *testing.T) {
	m := modelOnSet(t, procOnlySet())
	m.probes = noEBPFProbes()

	stats := renderIOStats(m.IOStats, m.ioKnown(), 40)
	for _, label := range []string{"fsyncs", "File opens"} {
		if line := lineWith(stats, label); !strings.Contains(line, "—") {
			t.Errorf("F5 %q = %q, want unmeasured", label, line)
		}
	}
	if line := lineWith(stats, "I/O wait"); strings.Contains(line, "—") {
		t.Errorf("F5 I/O wait has a collector here and should show its value: %q", line)
	}
	if line := lineWith(view(m, TabOverview), "fsyncs"); !strings.Contains(line, "fsyncs —") {
		t.Errorf("F1 fsyncs = %q, want unmeasured", line)
	}
}

// A panel that carries a real eBPF axis beside a sourceless one keeps the
// real one: memory switched off while the heap probe runs.
func TestPanelKeepsRealAxisBesideSourcelessOne(t *testing.T) {
	set := procOnlySet()
	set.MemProc = nil
	m := modelOnSet(t, set)
	m.probes = map[string]collector.ProbeStatus{
		collector.SubsystemMemory: {Name: collector.SubsystemMemory, State: collector.ProbeDisabled, Detail: "--disable memory"},
	}
	m.HeapStats = collector.HeapStats{
		TopCallSites: []collector.HeapCallSite{{Func: "main.handle", AllocBytes: 4096, AllocCount: 2}},
	}

	out := view(m, TabOverview)
	if !strings.Contains(out, "main.handle") {
		t.Errorf("heap detail hidden behind the memory panel's no-source notice:\n%s", out)
	}
	if line := lineWith(out, "RSS"); !strings.Contains(line, "—") {
		t.Errorf("RSS = %q beside a disabled memory subsystem, want unmeasured", line)
	}
}

// A real event lands on the timeline alone, and stays alone as the tick runs.
func TestRealTimelineEventStandsAlone(t *testing.T) {
	m := modelOnSet(t, procOnlySet())

	ev := collector.TimelineEvent{Timestamp: time.Now(), Category: "fd", Message: "openat fd=3 /etc/hosts"}
	next, _ := m.Update(TimelineMsg(ev))
	m = next.(Model)
	for i := 0; i < 500; i++ {
		m.tick()
	}

	if len(m.Timeline) != 1 || m.Timeline[0].Message != ev.Message {
		msgs := make([]string, 0, len(m.Timeline))
		for _, e := range m.Timeline {
			msgs = append(msgs, e.Message)
		}
		t.Errorf("timeline = %q, want only the published event", msgs)
	}
}

// With nothing attached the model is a demo, and everything the platform can
// provide is simulated as before.
func TestDemoStillSimulatesEverything(t *testing.T) {
	m := modelOnSet(t, &collector.Set{})
	if !m.demo {
		t.Fatal("an empty Set is the demo")
	}
	if len(m.Timeline) == 0 || len(m.FDEvents) == 0 || len(m.FDs) == 0 ||
		len(m.CPUHistory) == 0 || len(m.Threads) == 0 || len(m.NetConns) == 0 {
		t.Error("demo starts with empty panels")
	}
	for ps := srcCPU; ps <= srcLocks; ps++ {
		gone := (ps == srcSyscalls && syscallsUnavailable) ||
			(ps == srcIOFiles && ioFilesUnavailable) ||
			(ps == srcLocks && locksUnavailable)
		if reason, none := m.noSource(ps); none != gone {
			t.Errorf("demo: panel source %d reports no source = %v (%q), want %v", ps, none, reason, gone)
		}
	}
	before := len(m.Timeline)
	for i := 0; i < 50; i++ {
		m.tick()
	}
	if len(m.Timeline) <= before {
		t.Errorf("demo timeline did not advance: %d → %d", before, len(m.Timeline))
	}
	if line := lineWith(renderIOStats(m.IOStats, m.ioKnown(), 40), "fsyncs"); strings.Contains(line, "—") {
		t.Errorf("demo fsyncs render as unmeasured, but the demo supplies them: %q", line)
	}
}

func lineWith(s, substr string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, substr) {
			return l
		}
	}
	return ""
}
