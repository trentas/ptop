package bpf

import (
	"fmt"
	"strconv"
	"strings"
)

// parseCPUList parses the kernel's CPU-list format — the one
// /sys/devices/system/cpu/{online,possible} is written in — into the CPU ids it
// names. Ranges and single ids, comma separated, in ascending order:
//
//	"0-3"        → 0 1 2 3
//	"0,2-3,7"    → 0 2 3 7
//
// An empty string yields no ids and no error (a valid answer for
// /sys/devices/system/cpu/offline on a machine with none).
func parseCPUList(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, err := parseCPURange(part)
		if err != nil {
			return nil, err
		}
		for id := lo; id <= hi; id++ {
			out = append(out, id)
		}
	}
	return out, nil
}

func parseCPURange(part string) (lo, hi int, err error) {
	dash := strings.IndexByte(part, '-')
	if dash < 0 {
		id, err := strconv.Atoi(part)
		if err != nil || id < 0 {
			return 0, 0, fmt.Errorf("cpu list: bad entry %q", part)
		}
		return id, id, nil
	}
	lo, errLo := strconv.Atoi(part[:dash])
	hi, errHi := strconv.Atoi(part[dash+1:])
	if errLo != nil || errHi != nil || lo < 0 || hi < lo {
		return 0, 0, fmt.Errorf("cpu list: bad range %q", part)
	}
	return lo, hi, nil
}
