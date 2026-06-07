package collector

import "testing"

// A Set built for a non-positive PID starts nothing: every collector field is
// nil, every subsystem reports mock, and no source label is set. This is the
// path the TUI takes when run without a target (tests, --version, etc.).
func TestNewSetEmptyForNonPositivePID(t *testing.T) {
	for _, pid := range []int{0, -1} {
		s := NewSet(SetConfig{PID: pid})

		if s.FD != nil || s.CPUProc != nil || s.CPUEBPF != nil ||
			s.ThreadsProc != nil || s.ThreadsEBPF != nil ||
			s.MemProc != nil || s.MemEBPF != nil ||
			s.IOWait != nil || s.IOThroughput != nil ||
			s.SyscallsEBPF != nil || s.IOEBPF != nil ||
			s.NetworkEBPF != nil || s.FutexEBPF != nil {
			t.Errorf("pid=%d: expected all collectors nil, got %+v", pid, s)
		}

		if (s.Sources != Sources{}) {
			t.Errorf("pid=%d: expected empty Sources, got %+v", pid, s.Sources)
		}

		mocks := map[string]bool{
			"FDs":          s.MockFDs(),
			"CPU":          s.MockCPU(),
			"Threads":      s.MockThreads(),
			"Mem":          s.MockMem(),
			"IOWait":       s.MockIOWait(),
			"IOThroughput": s.MockIOThroughput(),
			"Syscalls":     s.MockSyscalls(),
			"IOFiles":      s.MockIOFiles(),
			"Net":          s.MockNet(),
		}
		for name, isMock := range mocks {
			if !isMock {
				t.Errorf("pid=%d: expected Mock%s() == true", pid, name)
			}
		}
	}
}

// Stop is idempotent and safe on an empty Set (all-nil fields) and on a nil
// receiver — the headless server and Model.Close both rely on this.
func TestSetStopIdempotent(t *testing.T) {
	s := NewSet(SetConfig{PID: 0})
	s.Stop()
	s.Stop() // second call must not panic

	var nilSet *Set
	nilSet.Stop() // nil receiver must not panic
}
