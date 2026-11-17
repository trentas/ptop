//go:build linux

package mcp

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// processUIDs reads the real, effective, saved and filesystem uids of pid from
// the Uid line of /proc/<pid>/status.
func processUIDs(pid int) ([]uint32, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return nil, err
	}
	return parseStatusUIDs(string(b))
}

func parseStatusUIDs(status string) ([]uint32, error) {
	for _, line := range strings.Split(status, "\n") {
		rest, ok := strings.CutPrefix(line, "Uid:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) != 4 {
			return nil, fmt.Errorf("Uid line has %d fields, want 4", len(fields))
		}
		out := make([]uint32, 0, 4)
		for _, f := range fields {
			n, err := strconv.ParseUint(f, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("Uid field %q: %w", f, err)
			}
			out = append(out, uint32(n))
		}
		return out, nil
	}
	return nil, fmt.Errorf("no Uid line")
}
