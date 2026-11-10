//go:build linux

package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/trentas/ptop/internal/bpf"
)

// ReadHostInfo reads the host's hardware class from /proc and /sys (#153).
func ReadHostInfo() HostInfo {
	var h HostInfo
	var u unix.Utsname
	if unix.Uname(&u) == nil {
		h.KernelRelease = unix.ByteSliceToString(u.Release[:])
		h.Machine = unix.ByteSliceToString(u.Machine[:])
	}
	var hvFlag, hasFlags bool
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		h.CPU, hvFlag, hasFlags = parseCPUInfo(string(b))
	}
	if n := countCPUList(readTrim("/sys/devices/system/cpu/online")); n > 0 {
		h.CPU.LogicalCPUs = n
	}
	h.CPU.SMT = readTrim("/sys/devices/system/cpu/smt/control")
	// Intel hybrid: the P and E cores each have a PMU of their own.
	var intel []CoreType
	for _, pmu := range []string{"cpu_core", "cpu_atom"} {
		if n := countCPUList(readTrim(filepath.Join("/sys/devices", pmu, "cpus"))); n > 0 {
			intel = append(intel, CoreType{Name: pmu, CPUs: n})
		}
	}
	if len(intel) > 0 {
		h.CPU.CoreTypes = intel
	}

	h.DMIVendor = readTrim("/sys/class/dmi/id/sys_vendor")
	h.DMIProduct = readTrim("/sys/class/dmi/id/product_name")
	switch xen := readTrim("/sys/hypervisor/type"); {
	case xen != "":
		h.Virt, h.Hypervisor = VirtVirtualized, xen
	case hvFlag:
		h.Virt, h.Hypervisor = VirtVirtualized, h.DMIVendor
	case hasFlags:
		h.Virt = VirtBareMetal
	}
	return h
}

// CgroupOf names the cgroup the process is in now, as /proc/<pid>/cgroup does.
func CgroupOf(pid int) (string, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	return parseCgroup(string(b)), nil
}

// ReadCgroupLimits reads a cgroup's v2 limits. cgroup is the path below the
// unified mount, as /proc/<pid>/cgroup names it.
func ReadCgroupLimits(cgroup string) CgroupLimits { return readCgroupLimitsAt(cgroupRoot, cgroup) }

func readCgroupLimitsAt(root, cgroup string) CgroupLimits {
	dir := filepath.Join(root, cgroup)
	return CgroupLimits{
		Cgroup:              cgroup,
		CPUMax:              readTrim(filepath.Join(dir, "cpu.max")),
		CPUWeight:           readTrim(filepath.Join(dir, "cpu.weight")),
		MemoryMax:           readTrim(filepath.Join(dir, "memory.max")),
		CpusetCPUsEffective: readTrim(filepath.Join(dir, "cpuset.cpus.effective")),
	}
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// hostInterval is the CPU axis's window, so steal lines up with on-CPU time.
const hostInterval = time.Second

// HostCollector publishes a HostSample every hostInterval: host steal and the
// target cgroup's limits (#153). /proc and /sys only, so it runs in --no-ebpf
// mode too. In pid mode the cgroup is re-resolved every sample, since a process
// can be moved; in cgroup mode it is the target.
type HostCollector struct {
	pid    int
	cgroup string // fixed in cgroup mode
	ch     chan interface{}
	stop   chan struct{}
	once   sync.Once

	prevSteal, prevTotal uint64
	havePrev             bool
}

func NewHostCollector() *HostCollector {
	return &HostCollector{ch: make(chan interface{}, 4), stop: make(chan struct{})}
}

func (c *HostCollector) Start(pid int) error {
	if _, err := CgroupOf(pid); err != nil {
		return fmt.Errorf("process %d cgroup unreadable: %w", pid, err)
	}
	c.pid = pid
	go c.loop()
	return nil
}

// StartCgroup targets a cgroup subtree: spec is a cgroup path or container id,
// resolved the way the eBPF filter resolves it.
func (c *HostCollector) StartCgroup(spec string) error {
	path, _, err := bpf.ResolveCgroupSpec(spec)
	if err != nil {
		return err
	}
	if c.cgroup = CgroupBelowRoot(path); c.cgroup == "" {
		return fmt.Errorf("cgroup %s is outside %s", path, cgroupRoot)
	}
	go c.loop()
	return nil
}

func (c *HostCollector) Stop()                         { c.once.Do(func() { close(c.stop) }) }
func (c *HostCollector) Subscribe() <-chan interface{} { return c.ch }

func (c *HostCollector) loop() {
	publish(c.ch, c.sample())
	t := time.NewTicker(hostInterval)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			publish(c.ch, c.sample())
		}
	}
}

func (c *HostCollector) sample() HostSample {
	s := HostSample{Timestamp: time.Now()}
	if b, err := os.ReadFile("/proc/stat"); err == nil {
		if steal, total, ok := cpuTimes(string(b)); ok {
			if c.havePrev {
				s.StealPct, s.StealKnown = stealPct(c.prevSteal, c.prevTotal, steal, total)
			}
			c.prevSteal, c.prevTotal, c.havePrev = steal, total, true
		}
	}
	cg := c.cgroup
	if cg == "" {
		cg, _ = CgroupOf(c.pid)
	}
	if cg != "" {
		s.Limits = ReadCgroupLimits(cg)
		s.Throttling, s.Pressure = readCgroupSaturationAt(cgroupRoot, cg)
	}
	return s
}

// readCgroupSaturationAt reads a cgroup's throttling and PSI (#151). Each is
// nil when its file is unreadable or carries no such counters.
func readCgroupSaturationAt(root, cgroup string) (*CPUThrottling, CgroupPressure) {
	dir := filepath.Join(root, cgroup)
	var thr *CPUThrottling
	if b, err := os.ReadFile(filepath.Join(dir, "cpu.stat")); err == nil {
		if t, ok := parseCPUStat(string(b)); ok {
			thr = &t
		}
	}
	read := func(name string) *Pressure {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil
		}
		p, ok := parsePressure(string(b))
		if !ok {
			return nil
		}
		return &p
	}
	return thr, CgroupPressure{CPU: read("cpu.pressure"), Memory: read("memory.pressure"), IO: read("io.pressure")}
}
