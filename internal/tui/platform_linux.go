//go:build linux

package tui

import (
	"os"
	"strings"

	"github.com/trentas/ptop/pkg/collector"
)

// Platform-specific feature availability flags. The help overlay branches on
// these so panel availability stays honest without scattering runtime.GOOS
// checks across the package. The source-string labels are owned by the
// collector package (collector.Source*) so collector.Set and the TUI agree on
// them; the aliases below keep the TUI's existing references working.

const (
	sourceProcEquivalent = collector.SourceProc
	sourceNetworkRich    = collector.SourceNetworkRich

	// Permanently-unavailable subsystems on this OS — the help overlay shows
	// a distinct "unavailable" status for these, instead of "mock", because
	// no toggle from the user side can make them work.
	syscallsUnavailable = false
	ioFilesUnavailable  = false
	locksUnavailable    = false
)

// platformSourceLabel is the footer's data-source descriptor on Linux: the
// lane that attached, the kernel, and where the CPU axis comes from. Each part
// is read from what the Set started, never from what this build could do. The
// kernel release is read live (it used to be hardcoded "6.8"), and the old
// unmeasured "overhead <0.5%" claim is gone.
//
// It used to end "sampling 100Hz", which described the CPU axis when that axis
// counted perf_event samples. It does not sample any more — it reads the
// scheduler's own accounting of the target's slices (#108) — so the claim
// went with the mechanism rather than being left to age into a lie.
//
// It was a constant until #149, "eBPF kernel <release> · cpu from
// sched_switch", and so it said that under --no-ebpf, and on a host where the
// cpu probe failed to attach and the axis fell back to /proc.
func platformSourceLabel(m Model) string {
	lane := collector.SourceProc
	if m.anyEBPF() {
		lane = "eBPF"
	}
	cpu := "no cpu source"
	switch m.cpuSource {
	case "eBPF":
		cpu = "cpu from sched_switch"
	case collector.SourceProc:
		cpu = "cpu from /proc"
	}
	return lane + " · kernel " + kernelRelease() + " · " + cpu
}

// kernelRelease returns the running kernel version (uname -r), or "?" if the
// procfs entry can't be read.
func kernelRelease() string {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(data))
}
