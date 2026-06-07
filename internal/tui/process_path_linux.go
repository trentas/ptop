//go:build linux

package tui

import (
	"fmt"
	"os"
)

// osExePath resolves the absolute executable path for pid via the
// /proc/<pid>/exe symlink — the same source `readlink` and most tools use.
// Returns "" when the link can't be read (process gone, permission denied).
func osExePath(pid int) string {
	p, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return p
}
