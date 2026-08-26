package collector

import (
	"os"
	"testing"
)

// --disable exists so an operator can be SURE which probes are running:
// ParseDisable rejects a typo rather than let it silently disable nothing,
// because the failure mode of a misspelled flag is a measurement that reports a
// configuration other than the one it ran. Three places took the flag and then
// started the collector anyway (#113) — memory on both lanes, threads and io on
// their /proc lane, and every subsystem in cgroup mode.
//
// One test per lane, because each was a separate omission and a regression in
// one would not show up in the others.

// pidSet builds a Set against this process with the named subsystems disabled.
func pidSet(t *testing.T, off ...string) *Set {
	t.Helper()
	disable := make(map[string]bool, len(off))
	for _, n := range off {
		disable[n] = true
	}
	s := NewSet(SetConfig{PID: os.Getpid(), Disable: disable})
	t.Cleanup(s.Stop)
	return s
}

// Memory consulted the flag nowhere: --disable memory parsed, validated, and
// started both the eBPF collector and the /proc reader behind it.
func TestDisableMemoryStopsBothLanes(t *testing.T) {
	s := pidSet(t, SubsystemMemory)
	if s.MemEBPF != nil || s.MemProc != nil {
		t.Errorf("memory collectors still running: ebpf=%v proc=%v", s.MemEBPF != nil, s.MemProc != nil)
	}
	if !s.MockMem() {
		t.Error("MockMem() = false — something is still feeding the memory view")
	}
	if s.Sources.Mem != "" {
		t.Errorf("Sources.Mem = %q, want empty", s.Sources.Mem)
	}
	if st := statusMap(t, s.Probes())[SubsystemMemory]; st.State != ProbeDisabled {
		t.Errorf("memory probe = %+v, want disabled", st)
	}
}

// Threads guarded only its eBPF lane, so --disable threads still polled
// /proc/<pid>/task.
func TestDisableThreadsStopsTheProcLane(t *testing.T) {
	s := pidSet(t, SubsystemThreads)
	if s.ThreadsEBPF != nil || s.ThreadsProc != nil {
		t.Errorf("thread collectors still running: ebpf=%v proc=%v", s.ThreadsEBPF != nil, s.ThreadsProc != nil)
	}
	if !s.MockThreads() {
		t.Error("MockThreads() = false")
	}
	if st := statusMap(t, s.Probes())[SubsystemThreads]; st.State != ProbeDisabled {
		t.Errorf("threads probe = %+v, want disabled", st)
	}
}

// io's iowait% and throughput lanes are not a fallback for the eBPF per-file
// view — they publish beside it, under the same category — and started
// unconditionally, so --disable io left io events on the wire.
func TestDisableIOStopsTheProcLanes(t *testing.T) {
	s := pidSet(t, SubsystemIO)
	if s.IOWait != nil || s.IOThroughput != nil || s.IOEBPF != nil {
		t.Errorf("io collectors still running: wait=%v throughput=%v ebpf=%v",
			s.IOWait != nil, s.IOThroughput != nil, s.IOEBPF != nil)
	}
	if !s.MockIOWait() || !s.MockIOThroughput() || !s.MockIOFiles() {
		t.Error("an io lane is still feeding the view")
	}
	if st := statusMap(t, s.Probes())[SubsystemIO]; st.State != ProbeDisabled {
		t.Errorf("io probe = %+v, want disabled", st)
	}
}

// CPU already honoured the flag on both lanes; pinned so the restructuring that
// fixed the others cannot quietly undo it.
func TestDisableCPUStopsBothLanes(t *testing.T) {
	s := pidSet(t, SubsystemCPU)
	if s.CPUEBPF != nil || s.CPUProc != nil {
		t.Errorf("cpu collectors still running: ebpf=%v proc=%v", s.CPUEBPF != nil, s.CPUProc != nil)
	}
	if st := statusMap(t, s.Probes())[SubsystemCPU]; st.State != ProbeDisabled {
		t.Errorf("cpu probe = %+v, want disabled", st)
	}
}

// Disabling one subsystem must not disturb its neighbours — the restructuring
// moved every lane inside a gate, and a misplaced brace would show up here.
func TestDisableIsScopedToWhatWasNamed(t *testing.T) {
	s := pidSet(t, SubsystemMemory)
	m := statusMap(t, s.Probes())
	for _, name := range []string{SubsystemCPU, SubsystemThreads, SubsystemFD} {
		if st := m[name]; st.State == ProbeDisabled {
			t.Errorf("%s reported disabled, but only memory was named: %+v", name, st)
		}
	}
}

// cgroup mode consulted the flag nowhere: --disable syscalls --cgroup /x.scope
// collected syscalls. The subtree is not reachable in a unit test, so the
// assertion is on the recorded outcome — disabled, never "asked for and failed".
func TestCgroupModeHonoursDisable(t *testing.T) {
	s := NewSet(SetConfig{
		Cgroup:  "/sys/fs/cgroup/nonexistent.scope",
		Disable: map[string]bool{SubsystemSyscalls: true},
	})
	defer s.Stop()
	if s.SyscallsEBPF != nil {
		t.Error("syscalls collector started in cgroup mode despite --disable syscalls")
	}
	st := statusMap(t, s.Probes())[SubsystemSyscalls]
	if st.State != ProbeDisabled {
		t.Errorf("syscalls probe = %+v, want disabled", st)
	}
	if st.Detail == "" {
		t.Error("a disabled probe must say what switched it off")
	}
}
