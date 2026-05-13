//go:build linux

package collector

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CPUCollector reads /proc/<pid>/stat polling every 500ms to compute the
// process CPU usage % via delta of (utime+stime) between samples.
//
// Works without root, without eBPF. On non-Linux hosts Start fails silently
// because /proc doesn't exist — the model keeps using simulated data.
type CPUCollector struct {
	pid  int
	ch   chan interface{}
	stop chan struct{}
	mu   sync.Mutex

	lastTicks    uint64
	lastSampleAt time.Time
}

func NewCPUCollector() *CPUCollector {
	return &CPUCollector{
		ch:   make(chan interface{}, 16),
		stop: make(chan struct{}),
	}
}

func (c *CPUCollector) Start(pid int) error {
	c.pid = pid
	if _, err := os.Stat(fmt.Sprintf("/proc/%d/stat", pid)); err != nil {
		return fmt.Errorf("process %d not found: %w", pid, err)
	}
	go c.loop()
	return nil
}

func (c *CPUCollector) Stop()                          { close(c.stop) }
func (c *CPUCollector) Subscribe() <-chan interface{}  { return c.ch }

func (c *CPUCollector) loop() {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			if s, err := c.sample(); err == nil {
				select {
				case c.ch <- s:
				default:
				}
			}
		}
	}
}

// clkTck is the kernel clock frequency (CONFIG_HZ), in ticks/second.
// Varies by architecture/distro:
//   - x86/x86_64: typically 100 (Ubuntu) or 250 (RHEL family)
//   - ARM/ARM64:  typically 250 (Ubuntu/Debian) or 1000 (Fedora ARM)
//
// Detected via `getconf CLK_TCK` (POSIX) — a single invocation at startup,
// negligible cost. Previously hardcoded to 100, which made CPU% 2.5x wrong
// on ARM (issue #18 follow-up).
var clkTck float64 = detectClkTck()

func detectClkTck() float64 {
	out, err := exec.Command("getconf", "CLK_TCK").Output()
	if err == nil {
		if v, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64); err == nil && v > 0 {
			return v
		}
	}
	return 100 // reasonable fallback
}

func (c *CPUCollector) sample() (CpuSample, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", c.pid))
	if err != nil {
		return CpuSample{}, err
	}
	utime, stime, _, _, _, err := parseProcStatTimes(data)
	if err != nil {
		return CpuSample{}, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	totalTicks := utime + stime

	var pct float64
	if !c.lastSampleAt.IsZero() {
		elapsed := now.Sub(c.lastSampleAt).Seconds()
		if elapsed > 0 {
			deltaTicks := float64(totalTicks - c.lastTicks)
			// single-core %: deltaTicks/clkTck = seconds of CPU used,
			// divided by elapsed = fraction of time. ×100 = %.
			pct = (deltaTicks / clkTck) / elapsed * 100
		}
	}
	c.lastTicks = totalTicks
	c.lastSampleAt = now

	return CpuSample{
		UsagePct:  pct,
		Timestamp: now,
	}, nil
}

// parseProcStatTimes extracts key numeric fields from /proc/<pid>/stat.
//
// Field 2 (comm) is parenthesized and MAY contain spaces/parens — the
// canonical parser looks for the LAST `)` on the line; everything after
// is fields 3..N space-separated. Index of post (post[i] = field i+3):
//
//	post[7]  = minflt              (field 10)
//	post[9]  = majflt              (field 12)
//	post[11] = utime               (field 14)
//	post[12] = stime               (field 15)
//	post[39] = delayacct_blkio_ticks (field 42)
//
// `blkio` returns 0 if the kernel doesn't export the field
// (CONFIG_TASK_DELAY_ACCT off, or kernel 5.14+ without `delayacct=on` boot param).
func parseProcStatTimes(data []byte) (utime, stime, minflt, majflt, blkio uint64, err error) {
	s := string(data)
	end := strings.LastIndex(s, ")")
	if end < 0 {
		return 0, 0, 0, 0, 0, fmt.Errorf("malformed /proc stat: missing ')'")
	}
	fields := strings.Fields(strings.TrimSpace(s[end+1:]))
	if len(fields) < 13 {
		return 0, 0, 0, 0, 0, fmt.Errorf("malformed /proc stat: %d fields", len(fields))
	}
	utime, _ = strconv.ParseUint(fields[11], 10, 64)
	stime, _ = strconv.ParseUint(fields[12], 10, 64)
	minflt, _ = strconv.ParseUint(fields[7], 10, 64)
	majflt, _ = strconv.ParseUint(fields[9], 10, 64)
	if len(fields) > 39 {
		blkio, _ = strconv.ParseUint(fields[39], 10, 64)
	}
	return
}
