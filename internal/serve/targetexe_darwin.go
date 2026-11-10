//go:build darwin

package serve

import "github.com/trentas/ptop/pkg/collector"

// targetExe names the target's executable, through libproc.
func targetExe(pid int) string {
	p, err := collector.ProcPath(pid)
	if err != nil {
		return ""
	}
	return p
}
