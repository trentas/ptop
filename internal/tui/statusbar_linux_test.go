//go:build linux

package tui

import (
	"strings"
	"testing"

	"github.com/trentas/ptop/pkg/collector"
)

// The footer names the lane that attached and where the cpu axis comes from,
// read from the Set rather than from the build. It used to be a constant and
// said "eBPF … · cpu from sched_switch" under --no-ebpf (#149).
func TestFooterNamesWhatAttached(t *testing.T) {
	active := func(name, source string) collector.ProbeStatus {
		return collector.ProbeStatus{Name: name, State: collector.ProbeActive, Source: source}
	}
	cases := []struct {
		name      string
		cpuSource string
		probes    map[string]collector.ProbeStatus
		want      []string
	}{
		{"--no-ebpf", collector.SourceProc, noEBPFProbes(),
			[]string{"/proc · kernel ", "cpu from /proc"}},
		{"cpu probe fell back to /proc", collector.SourceProc, map[string]collector.ProbeStatus{
			collector.SubsystemCPU:     active(collector.SubsystemCPU, collector.SourceProc),
			collector.SubsystemCPUProf: active(collector.SubsystemCPUProf, "eBPF"),
		}, []string{"eBPF · kernel ", "cpu from /proc"}},
		{"cpu via eBPF", "eBPF", map[string]collector.ProbeStatus{
			collector.SubsystemCPU: active(collector.SubsystemCPU, "eBPF"),
		}, []string{"eBPF · kernel ", "cpu from sched_switch"}},
		{"cpu disabled", "", map[string]collector.ProbeStatus{
			collector.SubsystemCPU: {Name: collector.SubsystemCPU, State: collector.ProbeDisabled, Detail: "--disable cpu"},
		}, []string{"/proc · kernel ", "no cpu source"}},
	}
	for _, tc := range cases {
		m := modelOnSet(t, procOnlySet())
		m.cpuSource, m.probes = tc.cpuSource, tc.probes
		bar := renderStatusBar(m)
		for _, w := range tc.want {
			if !strings.Contains(bar, w) {
				t.Errorf("%s: footer = %q, want %q", tc.name, strings.TrimSpace(bar), w)
			}
		}
		if tc.cpuSource != "eBPF" && strings.Contains(bar, "sched_switch") {
			t.Errorf("%s: footer claims sched_switch: %q", tc.name, strings.TrimSpace(bar))
		}
	}
}
