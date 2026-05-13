//go:build darwin

package tui

// See platform_linux.go for what these constants do.
//
// On macOS the "rich" eBPF tier doesn't exist; libproc is the public path.
// Three subsystems have no Tier 1 equivalent at all (per issue #22):
// syscalls (no public per-syscall trace), io-files (no per-file VFS hook),
// and locks (no __ulock_wait hook). The help overlay marks them as
// unavailable so the user understands the panels stay empty by design.

const (
	sourceProcEquivalent = "libproc"
	sourceNetworkRich    = "libproc"

	syscallsUnavailable = true
	ioFilesUnavailable  = true
	locksUnavailable    = true
)
