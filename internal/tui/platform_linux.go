//go:build linux

package tui

// Platform-specific labels and feature availability flags. The help overlay
// and the collector wiring code in model.go branch on these so the source
// string ("/proc" vs "libproc") and the panel availability stay honest
// without scattering runtime.GOOS checks across the package.

const (
	// sourceProcEquivalent labels the non-eBPF fallback source. "/proc" on
	// Linux, "libproc" on macOS.
	sourceProcEquivalent = "/proc"

	// sourceNetworkRich labels whatever path gives the rich network data
	// (TX/RX bytes, RTT, etc.). On Linux that's eBPF; macOS Tier 1 only has
	// the libproc-derived connection list, so it falls back to the
	// equivalent label there.
	sourceNetworkRich = "eBPF"

	// Permanently-unavailable subsystems on this OS — the help overlay shows
	// a distinct "unavailable" status for these, instead of "mock", because
	// no toggle from the user side can make them work.
	syscallsUnavailable = false
	ioFilesUnavailable  = false
	locksUnavailable    = false

	// statusBarSourceLabel is the footer's data-source descriptor. It must
	// describe how this build actually collects, never claim a path it can't
	// take (the macOS variant deliberately omits eBPF).
	statusBarSourceLabel = "eBPF kernel 6.8 · sampling 100Hz · overhead <0.5%"
)
