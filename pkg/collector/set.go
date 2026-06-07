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
}

// Sources records where each subsystem's real data came from. The value is
// one of "eBPF", SourceProc, or SourceNetworkRich — or "" when no real source
// started for that subsystem (the consumer then falls back to mock data).
// These strings surface in the TUI's "?" help overlay; never lie about them.
type Sources struct {
	CPU      string
	Threads  string
	Mem      string
	Syscalls string
	IOFiles  string
	Net      string
	Locks    string
}

// Set owns the live collectors for a single target PID, chosen by the
// source-priority rules (eBPF → /proc/libproc → mock). It is the single place
// that wires collector construction + lifecycle, so the TUI and the headless
// gRPC server (#51) consume the same selection logic instead of duplicating it.
type Set struct {
	FD           *FDCollector
	CPUProc      *CPUCollector
	CPUEBPF      *CPUEBPFCollector
	ThreadsProc  *ThreadsCollector
	ThreadsEBPF  *ThreadsEBPFCollector
	MemProc      *MemCollector
	MemEBPF      *MemEBPFCollector
	IOWait       *IOWaitCollector
	IOThroughput *IOThroughputCollector
	SyscallsEBPF *SyscallsEBPFCollector
	IOEBPF       *IOEBPFCollector
	NetworkEBPF  *NetworkEBPFCollector
	FutexEBPF    *FutexEBPFCollector

	Sources Sources
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
	if cfg.PID <= 0 {
		return s
	}

	if c := NewFDCollector(); c.Start(cfg.PID) == nil {
		s.FD = c
	} else if !cfg.NoEBPF {
		fmt.Fprintf(os.Stderr, "warning: FD collector unavailable\n")
	}

	// CPU: eBPF perf_event @ 100Hz/CPU first, /proc polling as fallback.
	if !cfg.NoEBPF {
		c := NewCPUEBPFCollector()
		if err := c.Start(cfg.PID); err == nil {
			s.CPUEBPF = c
			s.Sources.CPU = "eBPF"
		} else {
			warnEBPFFailure("cpu", err)
		}
	}
	if s.CPUEBPF == nil {
		if c := NewCPUCollector(); c.Start(cfg.PID) == nil {
			s.CPUProc = c
			s.Sources.CPU = SourceProc
		}
	}

	// Threads: eBPF (sched_switch → real-time CPU% + ctx switches) preferred,
	// /proc as fallback.
	if !cfg.NoEBPF {
		c := NewThreadsEBPFCollector()
		if err := c.Start(cfg.PID); err == nil {
			s.ThreadsEBPF = c
			s.Sources.Threads = "eBPF"
		} else {
			warnEBPFFailure("threads", err)
		}
	}
	if s.ThreadsEBPF == nil {
		if c := NewThreadsCollector(); c.Start(cfg.PID) == nil {
			s.ThreadsProc = c
			s.Sources.Threads = SourceProc
		}
	}

	// Memory: eBPF (real allocs/s + page faults via kprobe) preferred, /proc
	// (accumulated minflt+majflt) as fallback.
	if !cfg.NoEBPF {
		c := NewMemEBPFCollector()
		if err := c.Start(cfg.PID); err == nil {
			s.MemEBPF = c
			s.Sources.Mem = "eBPF"
		} else {
			warnEBPFFailure("memory", err)
		}
	}
	if s.MemEBPF == nil {
		if c := NewMemCollector(); c.Start(cfg.PID) == nil {
			s.MemProc = c
			s.Sources.Mem = SourceProc
		}
	}

	if c := NewIOWaitCollector(); c.Start(cfg.PID) == nil {
		s.IOWait = c
	}
	if c := NewIOThroughputCollector(); c.Start(cfg.PID) == nil {
		s.IOThroughput = c
	}

	// eBPF-only subsystems: only with -tags=ebpf, kernel >= 5.8 and
	// CAP_BPF/CAP_PERFMON. No /proc fallback — they stay mock otherwise.
	if !cfg.NoEBPF {
		c := NewSyscallsEBPFCollector()
		if err := c.Start(cfg.PID); err == nil {
			s.SyscallsEBPF = c
			s.Sources.Syscalls = "eBPF"
		} else {
			warnEBPFFailure("syscalls", err)
		}

		c2 := NewIOEBPFCollector()
		if err := c2.Start(cfg.PID); err == nil {
			s.IOEBPF = c2
			s.Sources.IOFiles = "eBPF"
		} else {
			warnEBPFFailure("io", err)
		}

		c3 := NewNetworkEBPFCollector()
		if err := c3.Start(cfg.PID); err == nil {
			s.NetworkEBPF = c3
			s.Sources.Net = SourceNetworkRich
		} else {
			warnEBPFFailure("network", err)
		}

		c4 := NewFutexEBPFCollector()
		if err := c4.Start(cfg.PID); err == nil {
			s.FutexEBPF = c4
			s.Sources.Locks = "eBPF"
		} else {
			warnEBPFFailure("futex", err)
		}
	}

	return s
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
	add(s.IOWait, s.IOWait != nil)
	add(s.IOThroughput, s.IOThroughput != nil)
	add(s.SyscallsEBPF, s.SyscallsEBPF != nil)
	add(s.IOEBPF, s.IOEBPF != nil)
	add(s.NetworkEBPF, s.NetworkEBPF != nil)
	add(s.FutexEBPF, s.FutexEBPF != nil)
	return cs
}

// Mock* report whether a subsystem has no real collector and must be
// simulated. They derive purely from which collectors started.

func (s *Set) MockFDs() bool          { return s.FD == nil }
func (s *Set) MockCPU() bool          { return s.CPUEBPF == nil && s.CPUProc == nil }
func (s *Set) MockThreads() bool      { return s.ThreadsEBPF == nil && s.ThreadsProc == nil }
func (s *Set) MockMem() bool          { return s.MemEBPF == nil && s.MemProc == nil }
func (s *Set) MockIOWait() bool       { return s.IOWait == nil }
func (s *Set) MockIOThroughput() bool { return s.IOThroughput == nil }
func (s *Set) MockSyscalls() bool     { return s.SyscallsEBPF == nil }
func (s *Set) MockIOFiles() bool      { return s.IOEBPF == nil }
func (s *Set) MockNet() bool          { return s.NetworkEBPF == nil }

// warnEBPFFailure reports an eBPF collector start failure to stderr, but only
// when this binary actually embeds eBPF (-tags=ebpf). Without it, the failure
// is expected and silent — the /proc fallback handles it.
func warnEBPFFailure(name string, err error) {
	if !bpf.Available {
		return
	}
	fmt.Fprintf(os.Stderr, "warning: eBPF %s collector unavailable: %v\n", name, err)
}
