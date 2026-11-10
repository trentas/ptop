//go:build linux

package collector

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadCgroupLimitsVerbatim(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "kubepods.slice", "pod.slice")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"cpu.max": "100000 100000\n", "cpu.weight": "39\n", "memory.max": "max\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := readCgroupLimitsAt(root, "/kubepods.slice/pod.slice")
	want := CgroupLimits{Cgroup: "/kubepods.slice/pod.slice", CPUMax: "100000 100000", CPUWeight: "39", MemoryMax: "max"}
	if got != want {
		t.Errorf("limits = %+v\nwant %+v (cpuset.cpus.effective absent reads as unknown)", got, want)
	}
}

// The host this runs on is the planted answer for what uname and sysfs say.
func TestReadHostInfoOnThisHost(t *testing.T) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		t.Skip(err)
	}
	h := ReadHostInfo()
	if h.KernelRelease != unix.ByteSliceToString(u.Release[:]) || h.Machine != unix.ByteSliceToString(u.Machine[:]) {
		t.Errorf("kernel %q on %q, uname says %q on %q", h.KernelRelease, h.Machine,
			unix.ByteSliceToString(u.Release[:]), unix.ByteSliceToString(u.Machine[:]))
	}
	if h.CPU.LogicalCPUs <= 0 {
		t.Errorf("logical CPUs = %d", h.CPU.LogicalCPUs)
	}
	if h.CPU.Vendor == "" {
		t.Error("no CPU vendor read from /proc/cpuinfo")
	}
}

func TestHostCollectorSamples(t *testing.T) {
	c := NewHostCollector()
	if err := c.Start(os.Getpid()); err != nil {
		t.Skip(err)
	}
	defer c.Stop()
	first := (<-c.Subscribe()).(HostSample)
	if first.StealKnown {
		t.Error("the first sample has no previous one, yet it carries steal")
	}
	cg, _ := CgroupOf(os.Getpid())
	if first.Limits.Cgroup != cg {
		t.Errorf("limits read from %q, the process is in %q", first.Limits.Cgroup, cg)
	}
	second := (<-c.Subscribe()).(HostSample)
	if !second.StealKnown || second.StealPct < 0 || second.StealPct > 100 {
		t.Errorf("second sample steal = %v (%v)", second.StealPct, second.StealKnown)
	}
}

func TestReadCgroupSaturationAbsentIsUnknown(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "a.slice")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("cpu.stat", "usage_usec 10\nnr_periods 0\nnr_throttled 0\nthrottled_usec 0\n")
	write("cpu.pressure", "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
	// memory.pressure and io.pressure missing: PSI unreadable for them.
	thr, p := readCgroupSaturationAt(root, "/a.slice")
	if thr == nil || *thr != (CPUThrottling{}) {
		t.Errorf("a quota-less cgroup with the cpu controller: throttling %+v, want present and zero", thr)
	}
	if p.CPU == nil || p.CPU.Full == nil || p.Memory != nil || p.IO != nil {
		t.Errorf("pressure = cpu %+v, memory %+v, io %+v; want cpu only", p.CPU, p.Memory, p.IO)
	}
}
