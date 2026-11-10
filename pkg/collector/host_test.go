package collector

import (
	"math"
	"reflect"
	"testing"
)

const cpuinfoX86VM = `processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 143
model name	: Intel(R) Xeon(R) Platinum 8488C
stepping	: 8
microcode	: 0x2b000603
flags		: fpu vme de pse tsc msr hypervisor lahf_lm

processor	: 1
vendor_id	: GenuineIntel
cpu family	: 6
model		: 143
model name	: Intel(R) Xeon(R) Platinum 8488C
stepping	: 8
microcode	: 0x2b000603
flags		: fpu vme de pse tsc msr hypervisor lahf_lm
`

func TestParseCPUInfoX86(t *testing.T) {
	cpu, hv, hasFlags := parseCPUInfo(cpuinfoX86VM)
	want := HostCPU{Vendor: "GenuineIntel", ModelName: "Intel(R) Xeon(R) Platinum 8488C", Family: "6",
		Model: "143", Stepping: "8", Microcode: "0x2b000603"}
	if !reflect.DeepEqual(cpu, want) {
		t.Errorf("cpu = %+v\nwant %+v", cpu, want)
	}
	if !hv || !hasFlags {
		t.Errorf("hypervisor flag = %v (flags line %v), want true", hv, hasFlags)
	}
	// "hypervisor" must be a whole flag, not a substring of another.
	if _, hv, _ := parseCPUInfo("processor : 0\nflags : fpu nohypervisorish\n"); hv {
		t.Error("a flag containing the word read as the hypervisor flag")
	}
}

// arm64 has no flags line, so it cannot say whether it is virtualized.
func TestParseCPUInfoArm64(t *testing.T) {
	text := "processor\t: 0\nBogoMIPS\t: 48.00\nFeatures\t: fp asimd\nCPU implementer\t: 0x41\nCPU architecture: 8\n" +
		"CPU variant\t: 0x3\nCPU part\t: 0xd0c\nCPU revision\t: 1\n\n" +
		"processor\t: 1\nCPU implementer\t: 0x41\nCPU architecture: 8\nCPU variant\t: 0x3\nCPU part\t: 0xd0c\nCPU revision\t: 1\n"
	cpu, hv, hasFlags := parseCPUInfo(text)
	want := HostCPU{Vendor: "0x41", Family: "8", Model: "0xd0c", Stepping: "1", Variant: "0x3"}
	if !reflect.DeepEqual(cpu, want) {
		t.Errorf("cpu = %+v\nwant %+v", cpu, want)
	}
	if hv || hasFlags {
		t.Errorf("arm64 read a hypervisor flag (%v) or a flags line (%v)", hv, hasFlags)
	}
}

// big.LITTLE: the processors differ, so each implementer:part is a core type.
func TestParseCPUInfoArm64Heterogeneous(t *testing.T) {
	var text string
	for i, part := range []string{"0xd05", "0xd05", "0xd05", "0xd05", "0xd0b", "0xd0b"} {
		text += "processor\t: " + string(rune('0'+i)) + "\nCPU implementer\t: 0x41\nCPU part\t: " + part + "\n\n"
	}
	cpu, _, _ := parseCPUInfo(text)
	want := []CoreType{{Name: "0x41:0xd05", CPUs: 4}, {Name: "0x41:0xd0b", CPUs: 2}}
	if !reflect.DeepEqual(cpu.CoreTypes, want) {
		t.Errorf("core types = %+v, want %+v", cpu.CoreTypes, want)
	}
	if cpu.Model != "0xd05" {
		t.Errorf("identity is the first processor's: model %q, want 0xd05", cpu.Model)
	}
	if homo, _, _ := parseCPUInfo(cpuinfoX86VM); homo.CoreTypes != nil {
		t.Errorf("identical processors gave core types %+v", homo.CoreTypes)
	}
}

func TestCountCPUList(t *testing.T) {
	for in, want := range map[string]int{"0-3": 4, "0": 1, "0-3,8,10-11\n": 7, "": 0, "3-1": -1, "x": -1} {
		if got := countCPUList(in); got != want {
			t.Errorf("countCPUList(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestStealFromProcStat(t *testing.T) {
	// user nice system idle iowait irq softirq steal guest guest_nice
	a := "cpu  1000 0 500 8000 100 0 50 350 200 0\ncpu0 1 2 3 4 5 6 7 8 9 10\n"
	b := "cpu  1100 0 550 8700 100 0 50 500 260 0\n"
	s1, t1, ok1 := cpuTimes(a)
	s2, t2, ok2 := cpuTimes(b)
	if !ok1 || !ok2 || s1 != 350 || t1 != 10000 || s2 != 500 || t2 != 11000 {
		t.Fatalf("cpu times = (%d, %d, %v) and (%d, %d, %v)", s1, t1, ok1, s2, t2, ok2)
	}
	// Guest time is already inside user, so it is not added again.
	pct, ok := stealPct(s1, t1, s2, t2)
	if !ok || math.Abs(pct-15) > 1e-9 {
		t.Errorf("steal = %v (%v), want 15%% (150 of 1000 jiffies)", pct, ok)
	}
	if _, ok := stealPct(s2, t2, s1, t1); ok {
		t.Error("a counter going backwards gave a steal reading")
	}
	if _, _, ok := cpuTimes("intr 1 2 3\n"); ok {
		t.Error("no cpu line, yet a reading")
	}
}

func TestCgroupBelowRoot(t *testing.T) {
	for in, want := range map[string]string{
		"/sys/fs/cgroup/kubepods.slice/pod.slice": "/kubepods.slice/pod.slice",
		"/sys/fs/cgroup":    "/",
		"/sys/fs/cgroupx/a": "",
		"/elsewhere":        "",
	} {
		if got := CgroupBelowRoot(in); got != want {
			t.Errorf("CgroupBelowRoot(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseCPUStat(t *testing.T) {
	withCPU := "usage_usec 519128\nuser_usec 518156\nsystem_usec 972\nnr_periods 25\nnr_throttled 25\nthrottled_usec 1973505\nnr_bursts 0\nburst_usec 0\n"
	got, ok := parseCPUStat(withCPU)
	if !ok || got != (CPUThrottling{NrPeriods: 25, NrThrottled: 25, ThrottledUsec: 1973505}) {
		t.Errorf("with the cpu controller: %+v (%v)", got, ok)
	}
	// Without the cpu controller cpu.stat has usage only: unknown, not zero.
	if _, ok := parseCPUStat("usage_usec 1824120584\nuser_usec 1494883766\nsystem_usec 329236818\n"); ok {
		t.Error("a cpu.stat without bandwidth counters read as throttling")
	}
}

func TestParsePressure(t *testing.T) {
	p, ok := parsePressure("some avg10=14.12 avg60=2.55 avg300=0.53 total=1819065\nfull avg10=1.00 avg60=0.50 avg300=0.10 total=60475\n")
	if !ok || p.Some != (PressureStall{Avg10: 14.12, Avg60: 2.55, Avg300: 0.53, TotalUsec: 1819065}) ||
		p.Full == nil || p.Full.TotalUsec != 60475 {
		t.Errorf("some+full = %+v, full %+v (%v)", p.Some, p.Full, ok)
	}
	// A kernel without a full line for this resource: full absent, not zero.
	p, ok = parsePressure("some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
	if !ok || p.Full != nil {
		t.Errorf("some only: full = %+v (%v)", p.Full, ok)
	}
	for _, bad := range []string{"", "full avg10=0 avg60=0 avg300=0 total=0\n", "some avg10=x avg60=0 avg300=0 total=0\n", "some avg10=0\n"} {
		if _, ok := parsePressure(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}
