package collector

import "testing"

// The collectors that claim cgroup targeting must actually satisfy the
// interface in every build configuration — including the stub builds, where the
// method exists to fail cleanly. A compile-time assertion is the whole point:
// NewSet's cgroup path takes CgroupTargeter, so a missing method is a build
// error rather than a runtime surprise.
var (
	_ CgroupTargeter = (*CPUEBPFCollector)(nil)
	_ CgroupTargeter = (*SyscallsEBPFCollector)(nil)
	_ CgroupTargeter = (*IOEBPFCollector)(nil)
	_ CgroupTargeter = (*NetworkEBPFCollector)(nil)
	_ CgroupTargeter = (*FutexEBPFCollector)(nil)
	_ CgroupTargeter = (*SecurityEBPFCollector)(nil)
)

// NewSet in cgroup mode must never touch the pid-shaped collectors, whatever
// happens with eBPF. On a host without it (this test's own build, unless it
// runs with -tags=ebpf as root) every StartCgroup fails and the Set comes back
// empty — the point being that it comes back at all, with no /proc collector
// silently started against a pid nobody asked about.
func TestNewSetCgroupModeStartsNoPIDCollectors(t *testing.T) {
	s := NewSet(SetConfig{Cgroup: "/sys/fs/cgroup/nonexistent-for-tests.scope"})
	defer s.Stop()

	if s.FD != nil || s.CPUProc != nil || s.ThreadsProc != nil || s.MemProc != nil ||
		s.IOWait != nil || s.IOThroughput != nil || s.ProcContext != nil {
		t.Error("cgroup mode started a /proc collector, which has no pid to read")
	}
	if s.HeapEBPF != nil || s.TLSEBPF != nil || s.SignalEBPF != nil || s.ProcLifecycleEBPF != nil {
		t.Error("cgroup mode started a pid-bound eBPF collector")
	}
	if s.MemEBPF != nil || s.ThreadsEBPF != nil {
		t.Error("cgroup mode started memory/threads, which read /proc/<pid> for their data")
	}
}

// A PID <= 0 with a cgroup set is still cgroup mode: the cgroup wins, and the
// absent pid must not send it down the pid path.
func TestNewSetCgroupModeIgnoresPID(t *testing.T) {
	s := NewSet(SetConfig{PID: 0, Cgroup: "/sys/fs/cgroup/nonexistent-for-tests.scope"})
	defer s.Stop()
	if s.FD != nil {
		t.Error("started the fd collector with no pid")
	}
}

// --no-ebpf in cgroup mode has nothing to fall back to, and must not quietly
// start a /proc collector instead.
func TestNewSetCgroupModeWithNoEBPF(t *testing.T) {
	s := NewSet(SetConfig{Cgroup: "/sys/fs/cgroup/x.scope", NoEBPF: true})
	defer s.Stop()
	if len(s.Collectors()) != 0 {
		t.Errorf("started %d collectors in --no-ebpf cgroup mode, want none", len(s.Collectors()))
	}
}
