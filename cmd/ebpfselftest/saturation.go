//go:build linux && ebpf

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/trentas/ptop/pkg/collector"
)

// ─── saturation: a known limit, throttled, then lifted (#151, #153) ────────
//
// A burner process wants a whole CPU and is put in a cgroup of its own capped
// at 20%. The kernel then throttles it in every 100ms period, for ~80ms of
// each, and its tasks stall on the CPU. Measured on this kind of host before
// the case existed: 20 of 20 periods throttled, 79.5% of wall time throttled,
// 71% of it in PSI cpu "some". Mid-case the limit is lifted to "max", the way
// an in-place pod resize changes it, and the next samples must say so.
//
// The case grades the HostSample the collector publishes for the burner's pid,
// not the files it reads.

const (
	saturationQuota  = "20000 100000"
	saturationLimitS = 2500 * time.Millisecond // limited phase
	saturationFreeS  = 3 * time.Second         // lifted phase
)

func checkSaturation(g *grader, _ int) {
	ctrl, err := os.ReadFile("/sys/fs/cgroup/cgroup.subtree_control")
	if err != nil || !hasField(string(ctrl), "cpu") {
		g.skip("saturation", "a cgroup with a CPU limit", "the cpu controller is not handed to /sys/fs/cgroup's children")
		return
	}
	dir := fmt.Sprintf("/sys/fs/cgroup/ptop-selftest-%d", os.Getpid())
	if err := os.Mkdir(dir, 0o755); err != nil {
		g.broken("saturation", "create a cgroup", err)
		return
	}
	defer os.Remove(dir)
	if err := os.WriteFile(filepath.Join(dir, "cpu.max"), []byte(saturationQuota), 0); err != nil {
		g.broken("saturation", "set cpu.max", err)
		return
	}

	burner := peerCmd("burn")
	if err := burner.Start(); err != nil {
		g.broken("saturation", "start the burner process", err)
		return
	}
	defer func() { _ = burner.Process.Kill(); _ = burner.Wait() }() // before the rmdir: a cgroup with a task cannot go
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(burner.Process.Pid)), 0); err != nil {
		g.broken("saturation", "move the burner into the cgroup", err)
		return
	}

	var lifted time.Time
	vals, err := collect(collector.NewHostCollector(), burner.Process.Pid, 0, func() {
		time.Sleep(saturationLimitS)
		lifted = time.Now()
		if err := os.WriteFile(filepath.Join(dir, "cpu.max"), []byte("max"), 0); err != nil {
			g.broken("saturation", "lift cpu.max", err)
		}
		time.Sleep(saturationFreeS)
	})
	if err != nil {
		g.broken("saturation", "attach", err)
		return
	}
	var limited, free []collector.HostSample
	for _, v := range vals {
		s, ok := v.(collector.HostSample)
		if !ok {
			continue
		}
		switch {
		case s.Limits.CPUMax == saturationQuota:
			limited = append(limited, s)
		case strings.HasPrefix(s.Limits.CPUMax, "max") && s.Timestamp.After(lifted):
			free = append(free, s)
		}
	}
	cg := "/" + filepath.Base(dir)
	if len(limited) < 2 {
		g.broken("saturation", "samples under the limit", fmt.Errorf("%d with cpu.max %q (want 2+), of %d", len(limited), saturationQuota, len(vals)))
		return
	}
	first, last := limited[0], limited[len(limited)-1]
	g.check("saturation", "the limits are the burner's cgroup's", last.Limits.Cgroup == cg,
		cg, last.Limits.Cgroup)

	wall := last.Timestamp.Sub(first.Timestamp)
	if g.check("saturation", "throttling is read under a CPU limit", first.Throttling != nil && last.Throttling != nil,
		"cpu.stat counters", presence(last.Throttling != nil)) {
		periods := last.Throttling.NrPeriods - first.Throttling.NrPeriods
		throttled := last.Throttling.NrThrottled - first.Throttling.NrThrottled
		g.check("saturation", fmt.Sprintf("periods throttled over %v at a 20%% quota", wall.Round(time.Millisecond)),
			periods >= uint64(wall/(200*time.Millisecond)) && throttled*10 >= periods*8,
			fmt.Sprintf("≥ %d periods, ≥ 80%% throttled", wall/(200*time.Millisecond)), fmt.Sprintf("%d of %d", throttled, periods))
		share := float64(last.Throttling.ThrottledUsec-first.Throttling.ThrottledUsec) / float64(wall.Microseconds())
		g.check("saturation", "time throttled, as a share of wall time", share >= 0.6 && share <= 0.95,
			"[60%, 95%] (80% planted)", fmt.Sprintf("%.0f%%", share*100))
	}
	if g.check("saturation", "PSI cpu is read", first.Pressure.CPU != nil && last.Pressure.CPU != nil,
		"cpu.pressure", presence(last.Pressure.CPU != nil)) {
		share := float64(last.Pressure.CPU.Some.TotalUsec-first.Pressure.CPU.Some.TotalUsec) / float64(wall.Microseconds())
		g.check("saturation", "PSI cpu some, as a share of wall time", share >= 0.4 && share <= 0.95,
			"[40%, 95%] (71% measured)", fmt.Sprintf("%.0f%%", share*100))
	}

	// Lifted: the new limit shows, and throttling is a measured zero, present
	// rather than absent.
	if !g.check("saturation", "the lifted limit shows in the samples after it (an in-place resize)", len(free) >= 2,
		`2+ samples with cpu.max "max …"`, fmt.Sprintf("%d", len(free))) {
		return
	}
	a, b := free[0], free[len(free)-1]
	if g.check("saturation", "throttling is still read with no limit", a.Throttling != nil && b.Throttling != nil,
		"cpu.stat counters", presence(b.Throttling != nil)) {
		got := b.Throttling.NrThrottled - a.Throttling.NrThrottled
		g.check("saturation", "no period throttled with no limit", got == 0, "0", fmt.Sprint(got))
	}
}

func hasField(s, w string) bool {
	for _, f := range strings.Fields(s) {
		if f == w {
			return true
		}
	}
	return false
}

func presence(ok bool) string {
	if ok {
		return "read"
	}
	return "absent"
}
