//go:build linux

package bpf

import (
	"strings"
	"testing"
)

// TestDiagnose_emptyWhenOK: when process is root + kernel supported, Diagnose is empty.
func TestDiagnose_emptyWhenOK(t *testing.T) {
	s := CapStatus{
		IsRoot:      true,
		KernelMajor: 6,
		KernelMinor: 0,
	}
	if got := s.Diagnose(); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestDiagnose_kernelTooOld(t *testing.T) {
	s := CapStatus{
		IsRoot:      true,
		KernelMajor: 5,
		KernelMinor: 4,
	}
	out := s.Diagnose()
	if !strings.Contains(out, "5.4") {
		t.Errorf("message should mention kernel version: %q", out)
	}
	if !strings.Contains(out, "5.8") {
		t.Errorf("message should mention 5.8 minimum: %q", out)
	}
	if !strings.Contains(out, "--no-ebpf") {
		t.Errorf("message should suggest --no-ebpf: %q", out)
	}
}

func TestDiagnose_missingCaps(t *testing.T) {
	s := CapStatus{
		IsRoot:      false,
		HasBPF:      false,
		HasPerfmon:  false,
		KernelMajor: 6, KernelMinor: 1,
	}
	out := s.Diagnose()
	for _, want := range []string{"CAP_BPF", "CAP_PERFMON", "sudo", "setcap", "--no-ebpf"} {
		if !strings.Contains(out, want) {
			t.Errorf("message does not contain %q: %s", want, out)
		}
	}
}

func TestDiagnose_unprivilegedDisabled(t *testing.T) {
	s := CapStatus{
		IsRoot:            false,
		HasBPF:            false,
		HasPerfmon:        false,
		KernelMajor:       6,
		KernelMinor:       1,
		UnprivBPFDisabled: 2,
	}
	out := s.Diagnose()
	if !strings.Contains(out, "unprivileged_bpf_disabled") {
		t.Errorf("message should explain unprivileged_bpf_disabled: %s", out)
	}
	if !strings.Contains(out, "sysctl") {
		t.Errorf("message should suggest sysctl: %s", out)
	}
}

func TestKernelSupportsBPF(t *testing.T) {
	cases := []struct {
		major, minor int
		want         bool
	}{
		{0, 0, true}, // unknown — assume ok, let the load fail
		{4, 19, false},
		{5, 4, false},
		{5, 8, true},
		{5, 15, true},
		{6, 0, true},
		{6, 5, true},
	}
	for _, c := range cases {
		s := CapStatus{KernelMajor: c.major, KernelMinor: c.minor}
		if got := s.KernelSupportsBPF(); got != c.want {
			t.Errorf("kernel %d.%d: got %v, expected %v", c.major, c.minor, got, c.want)
		}
	}
}

func TestCanLoadBPF(t *testing.T) {
	cases := []struct {
		s    CapStatus
		want bool
	}{
		{CapStatus{IsRoot: true}, true},
		{CapStatus{IsRoot: false, HasBPF: true, HasPerfmon: true}, true},
		{CapStatus{IsRoot: false, HasBPF: true, HasPerfmon: false}, false},
		{CapStatus{IsRoot: false, HasBPF: false, HasPerfmon: true}, false},
		{CapStatus{IsRoot: false}, false},
	}
	for _, c := range cases {
		if got := c.s.CanLoadBPF(); got != c.want {
			t.Errorf("status %+v: got %v, expected %v", c.s, got, c.want)
		}
	}
}
