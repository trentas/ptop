//go:build linux

package collector

import (
	"fmt"
	"os"
	"time"
)

// processCPU is the target's user + system CPU so far, from /proc/<pid>/stat,
// all threads together. Ticks of 1/clkTck second, so a window's figure is
// good to about 10ms: the overhead it divides is meant for --overhead-budget's
// windows in a row, not for one window alone.
func processCPU(pid int) (time.Duration, bool) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}
	_, _, ticks, ok := parseThreadStat(b)
	if !ok || clkTck <= 0 {
		return 0, false
	}
	return time.Duration(float64(ticks) / clkTck * float64(time.Second)), true
}
