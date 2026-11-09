//go:build linux

package serve

import "fmt"

// targetExe names the target's executable. The /proc link is opened, never
// resolved to a path first: it reaches the file through the target's own mount
// namespace, so a containerized target needs no path translation.
func targetExe(pid int) string { return fmt.Sprintf("/proc/%d/exe", pid) }
