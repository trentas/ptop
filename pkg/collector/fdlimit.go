package collector

import (
	"strconv"
	"strings"
)

// FDLimit is the target's RLIMIT_NOFILE, published by the fd collector beside
// each []FDEntry snapshot. Soft is the ceiling open, accept and dup run into
// (EMFILE); Hard is as far as the process may raise Soft by itself. Either may
// be FDLimitUnlimited.
//
// It exists so that "close to the limit" is measured against the limit. F6
// used to raise that alert above a fixed 20 open fds, carried over from the
// mockup's simulated data, and called 28 fds against a soft limit of 524288
// close to it.
//
// Linux only. macOS has no public API that reads another process's rlimits,
// so the collector there publishes none and the limit stays unknown.
type FDLimit struct {
	Soft uint64
	Hard uint64
}

// FDLimitUnlimited is RLIM_INFINITY, which /proc prints as "unlimited".
const FDLimitUnlimited = ^uint64(0)

// parseFDLimit reads the "Max open files" row of /proc/<pid>/limits:
//
//	Limit                     Soft Limit           Hard Limit           Units
//	Max open files            1024                 524288               files
func parseFDLimit(data string) (FDLimit, bool) {
	for _, line := range strings.Split(data, "\n") {
		rest, ok := strings.CutPrefix(line, "Max open files")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 2 {
			return FDLimit{}, false
		}
		soft, okS := parseRlimitValue(f[0])
		hard, okH := parseRlimitValue(f[1])
		if !okS || !okH {
			return FDLimit{}, false
		}
		return FDLimit{Soft: soft, Hard: hard}, true
	}
	return FDLimit{}, false
}

func parseRlimitValue(s string) (uint64, bool) {
	if s == "unlimited" {
		return FDLimitUnlimited, true
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil
}
