package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/trentas/ptop/pkg/collector"
)

// A probe the filter check failed mid-capture (#199): its panel stops showing
// what it read, which was the filter and not the target, and says why in the
// words of the failure rather than as an attach error. The change goes on the
// timeline in the probe's own category.
func TestAProbeFailedMidCaptureSaysWhy(t *testing.T) {
	set := &collector.Set{
		CPUEBPF:      &collector.CPUEBPFCollector{},
		SyscallsEBPF: &collector.SyscallsEBPFCollector{},
		IOWait:       &collector.IOWaitCollector{},
	}
	set.Sources.CPU, set.Sources.Syscalls = "eBPF", "eBPF"
	m := modelOnSet(t, set)
	m.probes = map[string]collector.ProbeStatus{
		collector.SubsystemCPU:      {Name: collector.SubsystemCPU, State: collector.ProbeActive, Source: "eBPF"},
		collector.SubsystemSyscalls: {Name: collector.SubsystemSyscalls, State: collector.ProbeActive, Source: "eBPF"},
		collector.SubsystemIO:       {Name: collector.SubsystemIO, State: collector.ProbeActive, Source: "eBPF"},
	}
	next, _ := m.Update(CpuMsg{UsagePct: 0, Timestamp: time.Now()})
	m = next.(Model)
	if _, none := m.noSource(srcCPU); none {
		t.Fatal("the cpu panel has no source before the change")
	}

	detail := collector.FilterBlindPrefix + ": in 3s /proc counted 57 context switches"
	for _, st := range []collector.ProbeStatus{
		{Name: collector.SubsystemCPU, State: collector.ProbeFailed, Detail: detail},
		{Name: collector.SubsystemSyscalls, State: collector.ProbeFailed, Detail: detail},
		{Name: collector.SubsystemIO, State: collector.ProbeActive, Source: collector.SourceProc,
			Detail: "iowait and throughput only, from /proc: the per-file eBPF lane is withheld. " + detail},
	} {
		next, _ = m.Update(ProbeChangeMsg{Timestamp: time.Now(), Status: st})
		m = next.(Model)
	}

	reason, none := m.noSource(srcCPU)
	if !none || !strings.HasPrefix(reason, "failed: "+collector.FilterBlindPrefix) {
		t.Errorf("cpu panel: %q (no source %v), want the filter's failure, not an attach error", reason, none)
	}
	if len(m.CPUHistory) != 0 {
		t.Errorf("cpu history kept %d readings of a blind filter", len(m.CPUHistory))
	}
	if !ioFilesUnavailable {
		if reason, none := m.noSource(srcIOFiles); !none || !strings.Contains(reason, collector.FilterBlindPrefix) {
			t.Errorf("io files panel: %q (no source %v), want the withdrawn lane's reason", reason, none)
		}
	}
	if _, none := m.noSource(srcIOWait); none {
		t.Error("iowait lost its /proc source with the eBPF lane")
	}
	if out := view(m, TabOverview); !strings.Contains(out, "failed: "+collector.FilterBlindPrefix) {
		t.Errorf("overview does not say why the cpu panel is empty:\n%s", out)
	}

	cats := map[string]bool{}
	for _, ev := range m.Timeline {
		if strings.Contains(ev.Message, "probe failed") || strings.Contains(ev.Message, "probe active") {
			cats[ev.Category] = true
		}
	}
	for _, want := range []string{"cpu", "syscall", "io"} {
		if !cats[want] {
			t.Errorf("timeline has no %q entry for the change: %v", want, m.Timeline)
		}
	}
}
