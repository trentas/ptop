package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/trentas/ptop/pkg/collector"
)

// A panel whose subsystem has no source says so, and why (#149).
//
// The TUI used to fill such a panel with simulated data, flagged only in the
// `?` overlay: invented connections, files and syscalls on screen beside a
// real target's real numbers, and nothing on the panel itself to tell them
// apart. Simulation now exists only in the demo (Model.demo, nothing
// attached). With a real target, a subsystem that has no source shows the
// reason its probe recorded: the flag that switched it off, the attach error,
// or the platform that has none.

// panelSource names a subsystem as the panels see it. It is finer than a
// probe: io is one probe, but its throughput, iowait and per-file views come
// from different lanes and can be present or absent independently.
type panelSource int

const (
	srcCPU panelSource = iota
	srcSyscalls
	srcThreads
	srcMemory
	srcNetwork
	srcFDs
	srcIOThroughput
	srcIOWait
	srcIOFiles
	srcLocks
)

// noSource reports whether ps has no source to show, and why. A subsystem the
// platform cannot provide has none even in the demo; any other is simulated in
// the demo and has no source only beside a real target.
func (m Model) noSource(ps panelSource) (string, bool) {
	var mock, platformGone bool
	var probe string
	switch ps {
	case srcCPU:
		mock, probe = m.usingMockCPU, collector.SubsystemCPU
	case srcSyscalls:
		mock, probe, platformGone = m.usingMockSyscalls, collector.SubsystemSyscalls, syscallsUnavailable
	case srcThreads:
		mock, probe = m.usingMockThreads, collector.SubsystemThreads
	case srcMemory:
		mock, probe = m.usingMockMem, collector.SubsystemMemory
	case srcNetwork:
		mock, probe = m.usingMockNet, collector.SubsystemNetwork
	case srcFDs:
		mock, probe = m.usingMockFDs, collector.SubsystemFD
	case srcIOThroughput:
		mock, probe = m.usingMockIOThrough, collector.SubsystemIO
	case srcIOWait:
		mock, probe = m.usingMockIOWait, collector.SubsystemIO
	case srcIOFiles:
		mock, probe, platformGone = m.usingMockIOFiles, collector.SubsystemIO, ioFilesUnavailable
	case srcLocks:
		// A lock graph in the model came from the futex probe, so it proves a
		// source the static label may not know about.
		mock, probe, platformGone = m.locksSource == "" && len(m.LockGraph) == 0, collector.SubsystemFutex, locksUnavailable
	}
	if platformGone {
		return "not available on macOS (see #22)", true
	}
	if m.demo || !mock {
		return "", false
	}
	return m.probeReason(probe, ps), true
}

// probeReason turns the probe set's record for a subsystem into the line a
// sourceless panel shows.
func (m Model) probeReason(probe string, ps panelSource) string {
	st, ok := m.probes[probe]
	if !ok {
		return "no collector started for this target"
	}
	switch st.State {
	case collector.ProbeDisabled:
		return "disabled: " + st.Detail
	case collector.ProbeFailed:
		return "failed to attach: " + st.Detail
	case collector.ProbeUnsupported:
		return st.Detail
	case collector.ProbeActive:
		// The probe runs, but not the lane this panel needs: io is active on
		// /proc (throughput, iowait) while the per-file view is eBPF-only.
		if ps == srcIOFiles {
			if m.cfg.NoEBPF {
				return "per-file I/O needs eBPF: disabled by --no-ebpf"
			}
			return "per-file I/O needs eBPF, and its probe did not attach (see ptop --caps)"
		}
	}
	return "no collector started for this target"
}

// renderNoSource is the body of a panel whose subsystem has no source: a
// marker, the reason word-wrapped to w, and a pointer to the overlay that
// lists every source, as far as h rows allow.
func renderNoSource(reason string, w, h int) string {
	if w <= 0 {
		return ""
	}
	marker := lipgloss.NewStyle().Foreground(ColorAmber).Background(ColorPanel).Bold(true).
		Render("○ no source")
	why := lipgloss.NewStyle().Foreground(ColorMuted).Background(ColorPanel).Italic(true).
		Width(w).Render(reason)
	lines := append([]string{marker}, strings.Split(why, "\n")...)
	lines = append(lines, DimStyle.Render("? lists every collector's source"))
	if h > 0 && len(lines) > h {
		lines = lines[:h]
	}
	return strings.Join(lines, "\n")
}

// noSourcePanel replaces a whole tab with one panel when its only subsystem
// has no source, the way F2 does for syscalls on macOS.
func noSourcePanel(title, reason string, w, h int) string {
	return Panel(title, renderNoSource(reason, w-2, h-3), w, h)
}

// orNoSource is body(), or the no-source body when ps has no source.
func (m Model) orNoSource(ps panelSource, w, h int, body func() string) string {
	if reason, ok := m.noSource(ps); ok {
		return renderNoSource(reason, w, h)
	}
	return body()
}

// has reports whether ps has something to show: a real source, or the demo.
func (m Model) has(ps panelSource) bool {
	_, none := m.noSource(ps)
	return !none
}
