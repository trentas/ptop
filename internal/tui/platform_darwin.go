//go:build darwin

package tui

import "github.com/trentas/ptop/internal/collector"

// See platform_linux.go for what these constants do.
//
// On macOS the "rich" eBPF tier doesn't exist; libproc is the public path.
// Three subsystems have no Tier 1 equivalent at all (per issue #22):
// syscalls (no public per-syscall trace), io-files (no per-file VFS hook),
// and locks (no __ulock_wait hook). The help overlay marks them as
// unavailable so the user understands the panels stay empty by design.

const (
	sourceProcEquivalent = collector.SourceProc
	sourceNetworkRich    = collector.SourceNetworkRich

	syscallsUnavailable = true
	ioFilesUnavailable  = true
	locksUnavailable    = true
)

// statusBarSourceLabel — no eBPF on macOS, so the footer must not claim it.
// Tier 1 collects via libproc + Mach (see issue #22).
func statusBarSourceLabel() string {
	return "libproc + Mach · Tier 1 · no eBPF"
}
