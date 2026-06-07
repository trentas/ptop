//go:build linux

package collector

// Source labels for the non-eBPF and rich-network data paths. They describe
// where a subsystem's data actually came from and surface in the TUI's "?"
// help overlay, so they must stay honest per platform.
const (
	// SourceProc labels the non-eBPF fallback source: "/proc" on Linux,
	// "libproc" on macOS.
	SourceProc = "/proc"

	// SourceNetworkRich labels whatever path gives the rich network data
	// (TX/RX bytes, RTT, ...). On Linux that's eBPF; macOS Tier 1 only has
	// the libproc-derived connection list.
	SourceNetworkRich = "eBPF"
)
