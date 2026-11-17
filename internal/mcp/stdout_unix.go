//go:build linux || darwin

package mcp

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// TakeStdout hands stdout to the protocol and points everything else at
// stderr.
//
// An MCP stdio session is the stdout stream: one stray write, from any line of
// ptop or a library under it, is a frame the client cannot parse, and the
// session breaks. Under --for a stray write cost one report; here it costs the
// session, and internal/bpf/memory.go was such a writer (#156). So the real
// stdout is moved to a new descriptor that only the protocol holds, and fd 1
// becomes a copy of stderr. A write through os.Stdout, fmt.Print or a C
// library then lands in the log, where it does no harm.
//
// Call it first, before anything could print, and only in --mcp mode.
func TakeStdout() (*os.File, error) {
	fd, err := unix.Dup(1)
	if err != nil {
		return nil, fmt.Errorf("dup stdout: %w", err)
	}
	unix.CloseOnExec(fd)
	if err := unix.Dup2(2, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("point stdout at stderr: %w", err)
	}
	return os.NewFile(uintptr(fd), "mcp-stdout"), nil
}
