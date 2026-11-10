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
