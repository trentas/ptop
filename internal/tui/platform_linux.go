//go:build linux

package tui

import (
	"os"
	"strings"

	"github.com/trentas/ptop/internal/collector"
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

// statusBarSourceLabel is the footer's data-source descriptor. It must
// describe how this build actually collects, never claim a path it can't
// take. The kernel release is read live (it used to be hardcoded "6.8"), and
// the old unmeasured "overhead <0.5%" claim is gone. The 100Hz figure is real
// — the eBPF cpu.bpf.c perf_event runs at sample_freq=100.
func statusBarSourceLabel() string {
	return "eBPF kernel " + kernelRelease() + " · sampling 100Hz"
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
