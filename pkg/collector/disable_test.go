package collector

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseDisable(t *testing.T) {
	cases := []struct {
		in   string
		want map[string]bool
	}{
		{"", nil},
		{"   ", nil},
		{",,", nil},
		{"heap", map[string]bool{"heap": true}},
		{"heap,tls", map[string]bool{"heap": true, "tls": true}},
		{" HEAP , Tls ", map[string]bool{"heap": true, "tls": true}},
		{"heap,heap", map[string]bool{"heap": true}},
	}
	for _, c := range cases {
		got, err := ParseDisable(c.in)
		if err != nil {
			t.Errorf("ParseDisable(%q): %v", c.in, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParseDisable(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// A typo must be an error. Accepting it would leave the subsystem running
// while the operator believes it is off — and in the benchmark, would measure
// one configuration and label it another.
func TestParseDisableRejectsUnknown(t *testing.T) {
	for _, bad := range []string{"heapp", "heap,tsl", "everything"} {
		_, err := ParseDisable(bad)
		if err == nil {
			t.Errorf("ParseDisable(%q) accepted an unknown subsystem", bad)
			continue
		}
		// The error must say what IS accepted; a bare rejection leaves the
		// operator guessing at the spelling.
		if !strings.Contains(err.Error(), "heap") {
			t.Errorf("ParseDisable(%q) error does not list the known names: %v", bad, err)
		}
	}
}

func TestKnownSubsystemsIsSortedAndComplete(t *testing.T) {
	got := KnownSubsystems()
	for _, name := range []string{
		SubsystemCPU, SubsystemThreads, SubsystemMemory, SubsystemHeap,
		SubsystemSyscalls, SubsystemIO, SubsystemNetwork, SubsystemFutex,
		SubsystemSignals, SubsystemLifecycle, SubsystemSecurity, SubsystemTLS,
		SubsystemFD,
	} {
		if !strings.Contains(got, name) {
			t.Errorf("KnownSubsystems() omits %q: %s", name, got)
		}
		if _, err := ParseDisable(name); err != nil {
			t.Errorf("ParseDisable rejects its own constant %q: %v", name, err)
		}
	}
	parts := strings.Split(got, ", ")
	for i := 1; i < len(parts); i++ {
		if parts[i-1] > parts[i] {
			t.Errorf("KnownSubsystems() is not sorted: %s", got)
			break
		}
	}
}

func TestSetConfigOff(t *testing.T) {
	cfg := SetConfig{Disable: map[string]bool{SubsystemHeap: true}}
	if !cfg.off(SubsystemHeap) {
		t.Error("off(heap) = false with heap disabled")
	}
	if cfg.off(SubsystemCPU) {
		t.Error("off(cpu) = true with only heap disabled")
	}
	// The nil map is the default and must mean "nothing disabled", not panic.
	if (SetConfig{}).off(SubsystemHeap) {
		t.Error("off() on a zero SetConfig disabled something")
	}
}

// NewSet must honour Disable even in the no-eBPF path, where the /proc
// collectors are the ones that would otherwise start.
func TestNewSetHonoursDisableWithoutEBPF(t *testing.T) {
	full := NewSet(SetConfig{PID: 1, NoEBPF: true})
	defer full.Stop()

	off := NewSet(SetConfig{PID: 1, NoEBPF: true, Disable: map[string]bool{
		SubsystemCPU: true, SubsystemFD: true,
	}})
	defer off.Stop()

	if off.CPUProc != nil || off.CPUEBPF != nil {
		t.Error("cpu collector started despite --disable cpu")
	}
	if off.FD != nil {
		t.Error("fd collector started despite --disable fd")
	}
	if len(off.Collectors()) >= len(full.Collectors()) {
		t.Errorf("disabling subsystems did not reduce the collector set: %d vs %d",
			len(off.Collectors()), len(full.Collectors()))
	}
}
