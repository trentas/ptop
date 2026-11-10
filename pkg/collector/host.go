package collector

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ─── Host context (#153) ─────────────────────────────────────────────────────
//
// A consumer comparing two captures of one service must know whether the deploy
// between them also moved it to other hardware, under another hypervisor or
// another limit: each moves every CPU number and most latencies without a line
// of code changing. HostInfo is the hardware class, read once; HostSample is
// what changes at runtime. Nothing that identifies the box (hostname, instance
// id, DMI serial or UUID) is read.

// HostInfo is the hardware class of the target's host. An empty field is one
// ptop could not read.
type HostInfo struct {
	KernelRelease string // uname -r
	Machine       string // uname -m
	CPU           HostCPU
	Virt          Virtualization
	Hypervisor    string // /sys/hypervisor/type, else the DMI vendor of a virtualized host
	DMIVendor     string // /sys/class/dmi/id/sys_vendor
	DMIProduct    string // /sys/class/dmi/id/product_name
}

// IsZero reports whether nothing at all was read.
func (h HostInfo) IsZero() bool {
	return h.KernelRelease == "" && h.Machine == "" && h.CPU.IsZero() && h.Virt == VirtUnknown &&
		h.Hypervisor == "" && h.DMIVendor == "" && h.DMIProduct == ""
}

// HostCPU identifies the CPU as /proc/cpuinfo reports it for the first
// processor. x86 and arm64 name different things; the mapping is the wire's
// (HostCpu in proto/service.proto).
type HostCPU struct {
	Vendor, ModelName, Family, Model, Stepping, Variant, Microcode string
	LogicalCPUs                                                    int
	SMT                                                            string // smt/control verbatim
	CoreTypes                                                      []CoreType
}

func (c HostCPU) IsZero() bool {
	return c.Vendor == "" && c.ModelName == "" && c.Family == "" && c.Model == "" && c.Stepping == "" &&
		c.Variant == "" && c.Microcode == "" && c.LogicalCPUs == 0 && c.SMT == "" && len(c.CoreTypes) == 0
}

// CoreType is one kind of core on a heterogeneous CPU and how many CPUs have it.
type CoreType struct {
	Name string
	CPUs int
}

// Virtualization is whether the host runs under a hypervisor.
type Virtualization int

const (
	VirtUnknown     Virtualization = iota // nothing says: arm64 has no CPU flag for it
	VirtBareMetal                         // x86 without the cpuinfo "hypervisor" flag
	VirtVirtualized                       // the "hypervisor" flag, or /sys/hypervisor/type
)

// CgroupLimits are a cgroup v2 cgroup's limits, each file verbatim: "max" is
// unlimited and "" could not be read (cgroup v1, the root cgroup, a controller
// not enabled there). They are the cgroup's own; an ancestor's tighter limit
// also applies and is not read.
type CgroupLimits struct {
	Cgroup              string // as /proc/<pid>/cgroup names it
	CPUMax              string
	CPUWeight           string
	MemoryMax           string
	CpusetCPUsEffective string
}

// HostSample is what changes about the host while the target runs: steal on a
// VM, and the target cgroup's limits, which an in-place pod resize can change
// mid-capture.
type HostSample struct {
	Timestamp time.Time
	// StealPct is host-wide steal since the previous sample, as a share of all
	// CPU time. StealKnown is false on the first sample, which has no previous.
	StealPct   float64
	StealKnown bool
	Limits     CgroupLimits
	// Saturation of the target cgroup (#151), cumulative as the kernel keeps
	// it. nil is unreadable: no cpu controller for the cgroup, PSI off.
	Throttling *CPUThrottling
	Pressure   CgroupPressure
}

// CPUThrottling is cpu.stat's bandwidth accounting, cumulative.
type CPUThrottling struct {
	NrPeriods     uint64
	NrThrottled   uint64
	ThrottledUsec uint64
}

// CgroupPressure is the cgroup's PSI per resource; nil is unreadable.
type CgroupPressure struct {
	CPU, Memory, IO *Pressure
}

// Pressure is one PSI file. Full is nil where the kernel has no such line.
type Pressure struct {
	Some PressureStall
	Full *PressureStall
}

// PressureStall is one PSI line: percent stalled over 10s, 60s and 300s, and
// the stalled time since the cgroup was created.
type PressureStall struct {
	Avg10, Avg60, Avg300 float64
	TotalUsec            uint64
}

// parseCPUStat reads the bandwidth counters of a cgroup's cpu.stat. They are
// there only when the cpu controller is enabled for the cgroup, so their
// absence is reported as such (ok false), not as zeros.
func parseCPUStat(text string) (CPUThrottling, bool) {
	var t CPUThrottling
	seen := 0
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		v, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "nr_periods":
			t.NrPeriods = v
		case "nr_throttled":
			t.NrThrottled = v
		case "throttled_usec":
			t.ThrottledUsec = v
		default:
			continue
		}
		seen++
	}
	return t, seen == 3
}

// parsePressure reads a PSI file: a "some" line, and a "full" line where the
// kernel has one.
func parsePressure(text string) (Pressure, bool) {
	var p Pressure
	haveSome := false
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		st, ok := parsePressureStall(f[1:])
		if !ok {
			return Pressure{}, false
		}
		switch f[0] {
		case "some":
			p.Some, haveSome = st, true
		case "full":
			full := st
			p.Full = &full
		}
	}
	return p, haveSome
}

func parsePressureStall(kvs []string) (PressureStall, bool) {
	var st PressureStall
	seen := 0
	for _, kv := range kvs {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return st, false
		}
		var err error
		switch k {
		case "avg10":
			st.Avg10, err = strconv.ParseFloat(v, 64)
		case "avg60":
			st.Avg60, err = strconv.ParseFloat(v, 64)
		case "avg300":
			st.Avg300, err = strconv.ParseFloat(v, 64)
		case "total":
			st.TotalUsec, err = strconv.ParseUint(v, 10, 64)
		default:
			continue
		}
		if err != nil {
			return st, false
		}
		seen++
	}
	return st, seen == 4
}

// cgroupRoot is the cgroup-v2 unified mount point: the cgroup path the kernel
// names in /proc/<pid>/cgroup is below it, and so is its directory (whose inode
// is the cgroup id).
const cgroupRoot = "/sys/fs/cgroup"

// CgroupBelowRoot turns a cgroup directory into the path /proc/<pid>/cgroup
// would name it by ("/sys/fs/cgroup/a/b" → "/a/b"), "" when it is not below
// the unified mount.
func CgroupBelowRoot(dir string) string {
	rel, err := filepath.Rel(cgroupRoot, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return ""
	}
	if rel == "." {
		return "/"
	}
	return "/" + rel
}

// parseCPUInfo reads the identity of the first processor in /proc/cpuinfo,
// whether x86 says it runs under a hypervisor (and whether it could say:
// arm64 has no flags line), and the core types when the processors differ.
func parseCPUInfo(text string) (cpu HostCPU, hypervisorFlag, hasFlags bool) {
	type part struct{ impl, part string }
	var parts []part
	procs := 0
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "processor":
			procs++
			parts = append(parts, part{})
			continue
		case "CPU implementer":
			if procs > 0 {
				parts[procs-1].impl = v
			}
		case "CPU part":
			if procs > 0 {
				parts[procs-1].part = v
			}
		}
		if procs > 1 {
			continue // the identity is the first processor's
		}
		switch k {
		case "vendor_id", "CPU implementer":
			cpu.Vendor = v
		case "model name":
			cpu.ModelName = v
		case "cpu family", "CPU architecture":
			cpu.Family = v
		case "model", "CPU part":
			cpu.Model = v
		case "stepping", "CPU revision":
			cpu.Stepping = v
		case "CPU variant":
			cpu.Variant = v
		case "microcode":
			cpu.Microcode = v
		case "flags":
			hasFlags = true
			hypervisorFlag = hasWord(v, "hypervisor")
		}
	}

	// arm64 big.LITTLE and its kin: one entry per implementer:part when the
	// processors are not all the same. (Intel's hybrid types come from sysfs.)
	counts := map[string]int{}
	for _, p := range parts {
		if p.part != "" {
			counts[p.impl+":"+p.part]++
		}
	}
	if len(counts) > 1 {
		for name, n := range counts {
			cpu.CoreTypes = append(cpu.CoreTypes, CoreType{Name: name, CPUs: n})
		}
		sort.Slice(cpu.CoreTypes, func(i, j int) bool { return cpu.CoreTypes[i].Name < cpu.CoreTypes[j].Name })
	}
	return cpu, hypervisorFlag, hasFlags
}

func hasWord(s, w string) bool {
	for _, f := range strings.Fields(s) {
		if f == w {
			return true
		}
	}
	return false
}

// countCPUList counts the CPUs in a kernel CPU list ("0-3,8,10-11"), -1 when
// it does not parse.
func countCPUList(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	n := 0
	for _, r := range strings.Split(s, ",") {
		lo, hi, isRange := strings.Cut(r, "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			return -1
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil || b < a {
				return -1
			}
		}
		n += b - a + 1
	}
	return n
}

// cpuTimes reads the aggregate "cpu" line of /proc/stat: steal, and the total
// of user, nice, system, idle, iowait, irq, softirq and steal (guest time is
// already inside user and nice).
func cpuTimes(stat string) (steal, total uint64, ok bool) {
	for _, line := range strings.Split(stat, "\n") {
		f := strings.Fields(line)
		if len(f) < 9 || f[0] != "cpu" {
			continue
		}
		for i := 1; i <= 8; i++ {
			v, err := strconv.ParseUint(f[i], 10, 64)
			if err != nil {
				return 0, 0, false
			}
			total += v
			if i == 8 {
				steal = v
			}
		}
		return steal, total, true
	}
	return 0, 0, false
}

// stealPct is the steal share between two /proc/stat readings.
func stealPct(prevSteal, prevTotal, steal, total uint64) (float64, bool) {
	if total <= prevTotal || steal < prevSteal {
		return 0, false
	}
	return float64(steal-prevSteal) / float64(total-prevTotal) * 100, true
}
