//go:build darwin

package tui

import "github.com/trentas/ptop/internal/collector"

// osProcessName returns libproc's proc_name(), the macOS equivalent of
// /proc/<pid>/comm — same field `top -stats command` displays.
func osProcessName(pid int) string {
	name, err := collector.ProcName(pid)
	if err != nil {
		return ""
	}
	return name
}
