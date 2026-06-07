//go:build darwin

package tui

import "github.com/trentas/ptop/internal/collector"

// osExePath resolves the absolute executable path for pid via libproc's
// proc_pidpath — the macOS equivalent of readlink(/proc/<pid>/exe). Returns
// "" when the path can't be read (process gone, not owned by this euid).
func osExePath(pid int) string {
	p, err := collector.ProcPath(pid)
	if err != nil {
		return ""
	}
	return p
}
