//go:build linux

package tui

import (
	"fmt"
	"os"
)

// osProcessName reads /proc/<pid>/comm — same source `ps -o comm` uses.
// Length-capped by the kernel at TASK_COMM_LEN (16 chars including NUL).
func osProcessName(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return string(data)
}
