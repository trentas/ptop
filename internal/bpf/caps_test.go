//go:build linux

package bpf

import (
	"strings"
	"testing"
)

// TestDiagnose_emptyWhenOK: quando processo é root + kernel suportado, Diagnose vazio.
func TestDiagnose_emptyWhenOK(t *testing.T) {
	s := CapStatus{
		IsRoot:      true,
		KernelMajor: 6,
		KernelMinor: 0,
	}
	if got := s.Diagnose(); got != "" {
		t.Errorf("esperava vazio, got %q", got)
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
		t.Errorf("mensagem deveria citar versão do kernel: %q", out)
	}
	if !strings.Contains(out, "5.8") {
		t.Errorf("mensagem deveria citar mínimo 5.8: %q", out)
	}
	if !strings.Contains(out, "--no-ebpf") {
		t.Errorf("mensagem deveria sugerir --no-ebpf: %q", out)
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
			t.Errorf("mensagem não contém %q: %s", want, out)
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
		t.Errorf("mensagem deveria explicar unprivileged_bpf_disabled: %s", out)
	}
	if !strings.Contains(out, "sysctl") {
		t.Errorf("mensagem deveria sugerir sysctl: %s", out)
	}
}

func TestKernelSupportsBPF(t *testing.T) {
	cases := []struct {
		major, minor int
		want         bool
	}{
		{0, 0, true}, // desconhecido — assume ok, deixa load falhar
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
			t.Errorf("kernel %d.%d: got %v, esperado %v", c.major, c.minor, got, c.want)
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
			t.Errorf("status %+v: got %v, esperado %v", c.s, got, c.want)
		}
	}
}
