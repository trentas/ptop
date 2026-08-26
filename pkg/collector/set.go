package collector

import (
	"fmt"
	"os"

	"github.com/trentas/ptop/internal/bpf"
)

// SetConfig parameterizes which collectors a Set starts.
type SetConfig struct {
	PID    int
	NoEBPF bool // degraded mode: skip eBPF, use /proc (or libproc on macOS) only

	// Cgroup, when set, targets every process in that cgroup subtree instead of
	// one PID (#94) — a cgroup path or a container id. It takes precedence over
	// PID and starts a deliberately smaller set of collectors; see NewSet.
	Cgroup string

	// TLS opts into pre-encryption payload capture via libssl uprobes (#55) —
	// OFF by default (privacy). TLSMaxBytes caps the plaintext copied per call
	// (0 = metadata only: direction/fd/byte count, no payload bytes).
	TLS         bool
	TLSMaxBytes int

	// Disable names subsystems to skip entirely, keyed by the constants in
	// disable.go. Nil starts everything the platform supports. See disable.go
	// for why this exists — chiefly that probe costs differ by orders of
	// magnitude, and the expensive one is nameable.
	Disable map[string]bool

	// HeapSampleBytes is the Go allocation lane's stack-sampling rate: bytes
	// allocated between recorded samples (#108).
	//
	// 0 takes bpf.GoAllocDefaultSampleBytes. The zero value has to be the
	// cheap configuration, not the exhaustive one: recording every allocation
	// costs a large multiple of the TARGET's own CPU time, and a caller that
	// simply did not fill this field must not get that by omission. Ask for it
	// explicitly with HeapSampleEveryAllocation.
	HeapSampleBytes uint64
}

// HeapSampleEveryAllocation is the HeapSampleBytes value that records every
// allocation rather than sampling: a rate of one byte, which any allocation
// crosses immediately (mallocgc calls of size 0 are dropped before this). Exact
// per call site, and on an allocation-heavy target a different program from the
// one being observed — see bench/ for what it costs.
const HeapSampleEveryAllocation uint64 = 1

// heapSampleBytes resolves the configured rate, filling in the default for the
// zero value.
func heapSampleBytes(cfg SetConfig) uint64 {
	if cfg.HeapSampleBytes == 0 {
		return bpf.GoAllocDefaultSampleBytes
	}
	return cfg.HeapSampleBytes
}

// Sources records where each subsystem's real data came from. The value is
// one of "eBPF", SourceProc, or SourceNetworkRich — or "" when no real source
// started for that subsystem (the consumer then falls back to mock data).
// These strings surface in the TUI's "?" help overlay; never lie about them.
type Sources struct {
	CPU       string
	Threads   string
	Mem       string
	Heap      string
	Syscalls  string
	IOFiles   string
	Net       string
	Locks     string
	Signals   string
	TLS       string
	Context   string
	Lifecycle string
	Security  string
}

// Set owns the live collectors for a single target PID, chosen by the
// source-priority rules (eBPF → /proc/libproc → mock). It is the single place
// that wires collector construction + lifecycle, so the TUI and the headless
// gRPC server (#51) consume the same selection logic instead of duplicating it.
type Set struct {
	FD                *FDCollector
	CPUProc           *CPUCollector
	CPUEBPF           *CPUEBPFCollector
	ThreadsProc       *ThreadsCollector
	ThreadsEBPF       *ThreadsEBPFCollector
	MemProc           *MemCollector
	MemEBPF           *MemEBPFCollector
	HeapEBPF          *HeapEBPFCollector
	IOWait            *IOWaitCollector
	IOThroughput      *IOThroughputCollector
	SyscallsEBPF      *SyscallsEBPFCollector
	IOEBPF            *IOEBPFCollector
	NetworkEBPF       *NetworkEBPFCollector
	FutexEBPF         *FutexEBPFCollector
	SignalEBPF        *SignalEBPFCollector
	TLSEBPF           *TLSEBPFCollector
	ProcContext       *ProcContextCollector
	ProcLifecycleEBPF *ProcLifecycleEBPFCollector
	SecurityEBPF      *SecurityEBPFCollector

	Sources Sources

	// probes records what became of every subsystem — including the ones that
	// produced nothing, and why. Read it through Probes().
	probes probeLog
}

// Probes reports every collector this Set tried to run and what became of it,
// sorted by name (#112).
//
// Sources answers "where did this number come from" for the TUI; this answers
// "was anything watching at all", which is the question a consumer diffing two
// captures has to settle before it compares them. An empty slice means nothing
// was attempted (PID <= 0).
func (s *Set) Probes() []ProbeStatus {
	if s == nil {
		return nil
	}
	return s.probes.statuses()
}

// NewSet starts the collectors for cfg.PID following the per-subsystem source
// priority and returns the populated Set. A PID <= 0 yields an empty Set (no
// collector started, every Mock* true) — the consumer simulates everything.
//
// eBPF start failures are logged to stderr (before any alt-screen) via
// warnEBPFFailure; the corresponding /proc fallback is then attempted. Each
// collector that fails to start is left nil.
func NewSet(cfg SetConfig) *Set {
	s := &Set{}
	if cfg.Cgroup != "" {
		s.startCgroup(cfg)
		return s
	}
	if cfg.PID <= 0 {
		return s
	}

	if cfg.off(SubsystemFD) {
		s.probes.disabled(SubsystemFD, "--disable "+SubsystemFD)
	} else if c := NewFDCollector(); c.Start(cfg.PID) == nil {
		s.FD = c
		s.probes.active(SubsystemFD, SourceProc)
	} else {
		s.probes.unsupported(SubsystemFD, "FD collector unavailable for this target")
		if !cfg.NoEBPF {
			fmt.Fprintf(os.Stderr, "warning: FD collector unavailable\n")
		}
	}

	// CPU: eBPF (the target's on-CPU time, from sched_switch) first, /proc
	// polling of utime+stime as fallback.
	if cfg.off(SubsystemCPU) {
		s.probes.disabled(SubsystemCPU, "--disable "+SubsystemCPU)
	}
	if !cfg.NoEBPF && !cfg.off(SubsystemCPU) {
		c := NewCPUEBPFCollector()
		if err := c.Start(cfg.PID); err == nil {
			s.CPUEBPF = c
			s.Sources.CPU = "eBPF"
			s.probes.active(SubsystemCPU, "eBPF")
		} else {
			warnEBPFFailure("cpu", err)
			s.probes.failed(SubsystemCPU, err, bpf.Available)
		}
	}
	if s.CPUEBPF == nil && !cfg.off(SubsystemCPU) {
		if c := NewCPUCollector(); c.Start(cfg.PID) == nil {
			s.CPUProc = c
			s.Sources.CPU = SourceProc
			s.probes.active(SubsystemCPU, SourceProc)
		}
	}

	// Threads: eBPF (sched_switch → real-time CPU% + ctx switches) preferred,
	// /proc as fallback.
	if cfg.off(SubsystemThreads) {
		s.probes.disabled(SubsystemThreads, "--disable "+SubsystemThreads)
	}
	if !cfg.NoEBPF && !cfg.off(SubsystemThreads) {
		c := NewThreadsEBPFCollector()
		if err := c.Start(cfg.PID); err == nil {
			s.ThreadsEBPF = c
			s.Sources.Threads = "eBPF"
			s.probes.active(SubsystemThreads, "eBPF")
		} else {
			warnEBPFFailure("threads", err)
			s.probes.failed(SubsystemThreads, err, bpf.Available)
		}
	}
	if s.ThreadsEBPF == nil {
		if c := NewThreadsCollector(); c.Start(cfg.PID) == nil {
			s.ThreadsProc = c
			s.Sources.Threads = SourceProc
			s.probes.active(SubsystemThreads, SourceProc)
		}
	}

	// Memory: eBPF (real allocs/s + page faults via kprobe) preferred, /proc
	// (accumulated minflt+majflt) as fallback.
	if !cfg.NoEBPF {
		c := NewMemEBPFCollector()
		if err := c.Start(cfg.PID); err == nil {
			s.MemEBPF = c
			s.Sources.Mem = "eBPF"
			s.probes.active(SubsystemMemory, "eBPF")
		} else {
			warnEBPFFailure("memory", err)
			s.probes.failed(SubsystemMemory, err, bpf.Available)
		}
	}
	if s.MemEBPF == nil {
		if c := NewMemCollector(); c.Start(cfg.PID) == nil {
			s.MemProc = c
			s.Sources.Mem = SourceProc
			s.probes.active(SubsystemMemory, SourceProc)
		}
	}

	// iowait% and throughput come from /proc and publish under CATEGORY_IO
	// alongside the eBPF per-file view, so io is active on /proc whenever they
	// start and the richer lane did not. Recorded after the eBPF block below,
	// which gets first claim on the status.
	if c := NewIOWaitCollector(); c.Start(cfg.PID) == nil {
		s.IOWait = c
	}
	if c := NewIOThroughputCollector(); c.Start(cfg.PID) == nil {
		s.IOThroughput = c
	}

	// Execution/container context (#60): namespace + cgroup + uid/gid from
	// /proc. Pure /proc (no eBPF, no caps), so it starts even in --no-ebpf mode;
	// the !linux stub fails Start (ns/cgroup are Linux-only), leaving it nil.
	if c := NewProcContextCollector(); c.Start(cfg.PID) == nil {
		s.ProcContext = c
		s.Sources.Context = SourceProc
	}

	// eBPF-only subsystems: only with -tags=ebpf, kernel >= 5.8 and
	// CAP_BPF/CAP_PERFMON. No /proc fallback — they stay mock otherwise.
	//
	// Each goes through startEBPF so "disabled" and "failed to attach" are
	// handled the same way everywhere: a disabled subsystem is silent (it was
	// asked for), a failed one warns.
	if cfg.NoEBPF {
		// Degraded mode skips these entirely, so nothing below records them.
		// Saying so is the whole point: an eBPF-only subsystem is silent here by
		// the operator's choice, not because the target was quiet.
		for _, name := range ebpfOnlySubsystems {
			s.probes.disabled(name, "--no-ebpf")
		}
	}
	if !cfg.NoEBPF {
		startEBPF := func(name string, c ebpfStarter, onOK func()) {
			if cfg.off(name) {
				s.probes.disabled(name, "--disable "+name)
				return
			}
			if err := c.Start(cfg.PID); err != nil {
				warnEBPFFailure(name, err)
				s.probes.failed(name, err, bpf.Available)
				return
			}
			s.probes.active(name, "eBPF")
			onOK()
		}

		c := NewSyscallsEBPFCollector()
		startEBPF(SubsystemSyscalls, c, func() {
			s.SyscallsEBPF = c
			s.Sources.Syscalls = "eBPF"
		})

		c2 := NewIOEBPFCollector()
		startEBPF(SubsystemIO, c2, func() {
			s.IOEBPF = c2
			s.Sources.IOFiles = "eBPF"
		})

		c3 := NewNetworkEBPFCollector()
		startEBPF(SubsystemNetwork, c3, func() {
			s.NetworkEBPF = c3
			s.Sources.Net = SourceNetworkRich
		})

		c4 := NewFutexEBPFCollector()
		startEBPF(SubsystemFutex, c4, func() {
			s.FutexEBPF = c4
			s.Sources.Locks = "eBPF"
		})

		// Heap allocation tracking augments the memory subsystem: libc
		// malloc/free pairing, or runtime.mallocgc on a Go target. No /proc
		// fallback and no simulation — absent unless eBPF can attach.
		//
		// This is also the expensive one, by a wide margin: its probe fires
		// once per allocation, where the others fire on comparatively rare
		// kernel events. It is the subsystem --disable exists for.
		c5 := NewHeapEBPFCollector(heapSampleBytes(cfg))
		startEBPF(SubsystemHeap, c5, func() {
			s.HeapEBPF = c5
			s.Sources.Heap = "eBPF"
		})

		// Signals delivered to the target with their origin (#58).
		c6 := NewSignalEBPFCollector()
		startEBPF(SubsystemSignals, c6, func() {
			s.SignalEBPF = c6
			s.Sources.Signals = "eBPF"
		})

		// Exec lineage: fork/exec/exit across the target's descendant subtree (#60).
		c8 := NewProcLifecycleEBPFCollector()
		startEBPF(SubsystemLifecycle, c8, func() {
			s.ProcLifecycleEBPF = c8
			s.Sources.Lifecycle = "eBPF"
		})

		// Security: runtime PROT_EXEC mappings + best-effort SELinux LSM
		// denials (#59).
		c9 := NewSecurityEBPFCollector()
		startEBPF(SubsystemSecurity, c9, func() {
			s.SecurityEBPF = c9
			s.Sources.Security = "eBPF"
		})

		// TLS payload capture (#55) — OFF unless explicitly opted in (--tls),
		// because it observes plaintext.
		if cfg.TLS {
			c7 := NewTLSEBPFCollector(cfg.TLSMaxBytes)
			startEBPF(SubsystemTLS, c7, func() {
				s.TLSEBPF = c7
				s.Sources.TLS = "eBPF"
			})
		} else {
			s.probes.disabled(SubsystemTLS, "not opted in (--tls); payload capture observes plaintext")
		}
	}

	if s.IOWait != nil || s.IOThroughput != nil {
		s.probes.active(SubsystemIO, SourceProc)
	}

	return s
}

// ebpfStarter is the shape every eBPF collector shares: attach to a pid, or
// explain why not.
type ebpfStarter interface {
	Start(pid int) error
}

// startCgroup starts the collectors that can observe a whole cgroup subtree
// (#94). It is deliberately a smaller set than PID mode, and the omissions are
// structural rather than unfinished work:
//
//   - memory and threads read /proc/<pid>/statm and /proc/<pid>/task for RSS
//     and thread enumeration — a subtree has no single pid to read;
//   - heap and TLS attach uprobes into one process's mapped libc/libssl;
//   - signals and exec lineage filter on a global pid of their own.
//
// Of the ones that do start, io loses top-file paths and security loses
// symbolized call sites (both need /proc/<pid>), and network skips its /proc
// bootstrap of pre-existing connections. Each StartCgroup documents its own
// degradation.
//
// There is no /proc fallback and nothing is simulated here: cgroup targeting is
// an in-kernel filter, so without eBPF there is simply nothing to start.
func (s *Set) startCgroup(cfg SetConfig) {
	// The omissions are reported, not merely skipped: "this scope cannot observe
	// heap" and "heap was switched off" reach a consumer as the same silence
	// otherwise, and only the second is something an operator can undo.
	for name, why := range cgroupUnsupported {
		s.probes.unsupported(name, why)
	}

	if cfg.NoEBPF {
		fmt.Fprintln(os.Stderr, "warning: --cgroup targeting needs eBPF; nothing started in --no-ebpf mode")
		for _, name := range cgroupSubsystems {
			s.probes.disabled(name, "--no-ebpf (cgroup targeting is an in-kernel filter: without eBPF there is nothing to start)")
		}
		return
	}

	if c := NewCPUEBPFCollector(); s.startCgroupCollector(SubsystemCPU, c, cfg) {
		s.CPUEBPF = c
		s.Sources.CPU = "eBPF"
	}
	if c := NewSyscallsEBPFCollector(); s.startCgroupCollector(SubsystemSyscalls, c, cfg) {
		s.SyscallsEBPF = c
		s.Sources.Syscalls = "eBPF"
	}
	if c := NewIOEBPFCollector(); s.startCgroupCollector(SubsystemIO, c, cfg) {
		s.IOEBPF = c
		s.Sources.IOFiles = "eBPF"
	}
	if c := NewNetworkEBPFCollector(); s.startCgroupCollector(SubsystemNetwork, c, cfg) {
		s.NetworkEBPF = c
		s.Sources.Net = SourceNetworkRich
	}
	if c := NewFutexEBPFCollector(); s.startCgroupCollector(SubsystemFutex, c, cfg) {
		s.FutexEBPF = c
		s.Sources.Locks = "eBPF"
	}
	if c := NewSecurityEBPFCollector(); s.startCgroupCollector(SubsystemSecurity, c, cfg) {
		s.SecurityEBPF = c
		s.Sources.Security = "eBPF"
	}
}

// startCgroupCollector starts c against a cgroup subtree, reporting a failure
// — and a probe status — the same way PID mode does.
//
// cfg.off is deliberately NOT consulted: cgroup mode has never honoured
// --disable, and this change reports what ran, it does not change what runs.
// The status then says "active" for a subsystem the operator asked to switch
// off, which is the truth and is exactly how the gap became visible (#113).
func (s *Set) startCgroupCollector(name string, c CgroupTargeter, cfg SetConfig) bool {
	if err := c.StartCgroup(cfg.Cgroup); err != nil {
		warnEBPFFailure(name, err)
		s.probes.failed(name, err, bpf.Available)
		return false
	}
	s.probes.active(name, "eBPF")
	return true
}

// Stop stops every started collector. It is idempotent and safe to call on a
// Set with nil fields (PID <= 0, or collectors that never started). Required
// by the headless server, which must release eBPF tracers on shutdown; the TUI
// wires it into Model.Close() so tracers don't linger after exit.
func (s *Set) Stop() {
	if s == nil {
		return
	}
	if s.FD != nil {
		s.FD.Stop()
	}
	if s.CPUProc != nil {
		s.CPUProc.Stop()
	}
	if s.CPUEBPF != nil {
		s.CPUEBPF.Stop()
	}
	if s.ThreadsProc != nil {
		s.ThreadsProc.Stop()
	}
	if s.ThreadsEBPF != nil {
		s.ThreadsEBPF.Stop()
	}
	if s.MemProc != nil {
		s.MemProc.Stop()
	}
	if s.MemEBPF != nil {
		s.MemEBPF.Stop()
	}
	if s.HeapEBPF != nil {
		s.HeapEBPF.Stop()
	}
	if s.IOWait != nil {
		s.IOWait.Stop()
	}
	if s.IOThroughput != nil {
		s.IOThroughput.Stop()
	}
	if s.SyscallsEBPF != nil {
		s.SyscallsEBPF.Stop()
	}
	if s.IOEBPF != nil {
		s.IOEBPF.Stop()
	}
	if s.NetworkEBPF != nil {
		s.NetworkEBPF.Stop()
	}
	if s.FutexEBPF != nil {
		s.FutexEBPF.Stop()
	}
	if s.SignalEBPF != nil {
		s.SignalEBPF.Stop()
	}
	if s.TLSEBPF != nil {
		s.TLSEBPF.Stop()
	}
	if s.ProcContext != nil {
		s.ProcContext.Stop()
	}
	if s.ProcLifecycleEBPF != nil {
		s.ProcLifecycleEBPF.Stop()
	}
	if s.SecurityEBPF != nil {
		s.SecurityEBPF.Stop()
	}
}

// Collectors returns every started collector as a Collector. Used by consumers
// that fan-in all subscriptions generically (the headless gRPC server). Nil
// fields are skipped — appending a typed-nil pointer would yield a non-nil
// interface, so the explicit checks matter.
func (s *Set) Collectors() []Collector {
	if s == nil {
		return nil
	}
	var cs []Collector
	add := func(c Collector, ok bool) {
		if ok {
			cs = append(cs, c)
		}
	}
	add(s.FD, s.FD != nil)
	add(s.CPUProc, s.CPUProc != nil)
	add(s.CPUEBPF, s.CPUEBPF != nil)
	add(s.ThreadsProc, s.ThreadsProc != nil)
	add(s.ThreadsEBPF, s.ThreadsEBPF != nil)
	add(s.MemProc, s.MemProc != nil)
	add(s.MemEBPF, s.MemEBPF != nil)
	add(s.HeapEBPF, s.HeapEBPF != nil)
	add(s.IOWait, s.IOWait != nil)
	add(s.IOThroughput, s.IOThroughput != nil)
	add(s.SyscallsEBPF, s.SyscallsEBPF != nil)
	add(s.IOEBPF, s.IOEBPF != nil)
	add(s.NetworkEBPF, s.NetworkEBPF != nil)
	add(s.FutexEBPF, s.FutexEBPF != nil)
	add(s.SignalEBPF, s.SignalEBPF != nil)
	add(s.TLSEBPF, s.TLSEBPF != nil)
	add(s.ProcContext, s.ProcContext != nil)
	add(s.ProcLifecycleEBPF, s.ProcLifecycleEBPF != nil)
	add(s.SecurityEBPF, s.SecurityEBPF != nil)
	return cs
}

// Mock* report whether a subsystem has no real collector and must be
// simulated. They derive purely from which collectors started.

func (s *Set) MockFDs() bool          { return s.FD == nil }
func (s *Set) MockCPU() bool          { return s.CPUEBPF == nil && s.CPUProc == nil }
func (s *Set) MockThreads() bool      { return s.ThreadsEBPF == nil && s.ThreadsProc == nil }
func (s *Set) MockMem() bool          { return s.MemEBPF == nil && s.MemProc == nil }
func (s *Set) MockHeap() bool         { return s.HeapEBPF == nil }
func (s *Set) MockIOWait() bool       { return s.IOWait == nil }
func (s *Set) MockIOThroughput() bool { return s.IOThroughput == nil }
func (s *Set) MockSyscalls() bool     { return s.SyscallsEBPF == nil }
func (s *Set) MockIOFiles() bool      { return s.IOEBPF == nil }
func (s *Set) MockNet() bool          { return s.NetworkEBPF == nil }
func (s *Set) MockContext() bool      { return s.ProcContext == nil }

// warnEBPFFailure reports an eBPF collector start failure to stderr, but only
// when this binary actually embeds eBPF (-tags=ebpf). Without it, the failure
// is expected and silent — the /proc fallback handles it.
func warnEBPFFailure(name string, err error) {
	if !bpf.Available {
		return
	}
	fmt.Fprintf(os.Stderr, "warning: eBPF %s collector unavailable: %v\n", name, err)
}
