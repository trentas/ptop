package collector

import (
	"errors"
	"os"
	"testing"
)

func statusMap(t *testing.T, sts []ProbeStatus) map[string]ProbeStatus {
	t.Helper()
	m := make(map[string]ProbeStatus, len(sts))
	for _, st := range sts {
		if _, dup := m[st.Name]; dup {
			t.Fatalf("subsystem %q reported twice: %+v", st.Name, sts)
		}
		m[st.Name] = st
	}
	return m
}

// A Set that started nothing reports NO probes — not a set of inactive ones.
// The distinction is the whole contract: an empty list means "this server does
// not say", and a consumer must not read it as "nothing ran".
func TestProbesEmptyForNonPositivePID(t *testing.T) {
	for _, pid := range []int{0, -1} {
		s := NewSet(SetConfig{PID: pid})
		defer s.Stop()
		if got := s.Probes(); len(got) != 0 {
			t.Errorf("pid=%d: expected no probe statuses, got %+v", pid, got)
		}
	}
	var nilSet *Set
	if got := nilSet.Probes(); got != nil {
		t.Errorf("nil Set: expected nil, got %+v", got)
	}
}

// --disable names a subsystem, and the status says so with the flag that would
// undo it. This is the case #112 opens with: capture v1 with heap on and v2
// with it off, and every heap call site reads as removed unless the signature
// records that the probe was switched off.
func TestDisabledSubsystemIsReportedAsDisabled(t *testing.T) {
	s := NewSet(SetConfig{PID: os.Getpid(), Disable: map[string]bool{SubsystemHeap: true}})
	defer s.Stop()
	st, ok := statusMap(t, s.Probes())[SubsystemHeap]
	if !ok {
		t.Fatalf("heap absent from the probe set: %+v", s.Probes())
	}
	if st.State != ProbeDisabled {
		t.Errorf("heap state = %q, want %q", st.State, ProbeDisabled)
	}
	if st.Detail == "" {
		t.Error("a disabled probe must say what switched it off")
	}
}

// Degraded mode removes the eBPF-only subsystems rather than degrading them, so
// each is reported disabled — not simply absent, which is what an idle target
// looks like.
func TestNoEBPFReportsTheEBPFOnlySubsystemsDisabled(t *testing.T) {
	s := NewSet(SetConfig{PID: os.Getpid(), NoEBPF: true})
	defer s.Stop()
	m := statusMap(t, s.Probes())
	for _, name := range ebpfOnlySubsystems {
		st, ok := m[name]
		if !ok {
			t.Errorf("%s absent from the probe set", name)
			continue
		}
		if st.State != ProbeDisabled {
			t.Errorf("%s state = %q, want %q", name, st.State, ProbeDisabled)
		}
	}
}

// A cgroup subtree structurally cannot carry the per-process probes, and says
// so rather than staying silent: "this scope cannot observe heap" and "heap was
// switched off" are different facts, and only the second is actionable.
func TestCgroupScopeReportsItsStructuralOmissions(t *testing.T) {
	s := NewSet(SetConfig{Cgroup: "/sys/fs/cgroup/nonexistent.scope"})
	defer s.Stop()
	m := statusMap(t, s.Probes())
	for name, why := range cgroupUnsupported {
		st, ok := m[name]
		if !ok {
			t.Errorf("%s absent from the probe set in cgroup mode", name)
			continue
		}
		if st.State != ProbeUnsupported {
			t.Errorf("%s state = %q, want %q", name, st.State, ProbeUnsupported)
		}
		if st.Detail != why {
			t.Errorf("%s detail = %q, want %q", name, st.Detail, why)
		}
	}
}

// Statuses come back sorted, so two captures of one configuration report a
// byte-identical probe set — a consumer compares these as a key.
func TestProbeStatusesAreSorted(t *testing.T) {
	s := NewSet(SetConfig{PID: os.Getpid(), NoEBPF: true})
	defer s.Stop()
	sts := s.Probes()
	if len(sts) < 2 {
		t.Fatalf("expected several statuses, got %+v", sts)
	}
	for i := 1; i < len(sts); i++ {
		if sts[i-1].Name >= sts[i].Name {
			t.Fatalf("statuses not sorted by name: %+v", sts)
		}
	}
}

// A subsystem with a /proc fallback is walked twice — eBPF first, then /proc.
// Whichever lane produced data wins: the failure of the one must not overwrite
// the success of the other, in either order.
func TestActiveWinsOverAFailureInEitherOrder(t *testing.T) {
	boom := errors.New("attach: no tracefs")

	var failFirst probeLog
	failFirst.failed(SubsystemCPU, boom, true)
	failFirst.active(SubsystemCPU, SourceProc)
	if st := failFirst.statuses()[0]; st.State != ProbeActive || st.Source != SourceProc {
		t.Errorf("fail→active: got %+v, want active on %s", st, SourceProc)
	}

	var activeFirst probeLog
	activeFirst.active(SubsystemCPU, "eBPF")
	activeFirst.failed(SubsystemCPU, boom, true)
	if st := activeFirst.statuses()[0]; st.State != ProbeActive || st.Source != "eBPF" {
		t.Errorf("active→fail: got %+v, want active on eBPF", st)
	}
}

// A build with no eBPF programs embedded never had the probe: reporting that as
// FAILED would call every bare build a broken deployment, and a consumer acting
// on "failed to attach" would chase an infrastructure problem that isn't there.
func TestNoEBPFBuildIsUnsupportedNotFailed(t *testing.T) {
	var l probeLog
	l.failed(SubsystemSyscalls, errors.New("no program embedded"), false)
	if st := l.statuses()[0]; st.State != ProbeUnsupported {
		t.Errorf("state = %q, want %q (detail %q)", st.State, ProbeUnsupported, st.Detail)
	}

	var withEBPF probeLog
	withEBPF.failed(SubsystemSyscalls, errors.New("permission denied"), true)
	st := withEBPF.statuses()[0]
	if st.State != ProbeFailed {
		t.Errorf("state = %q, want %q", st.State, ProbeFailed)
	}
	if st.Detail != "permission denied" {
		t.Errorf("detail = %q, want the attach error verbatim", st.Detail)
	}
}
