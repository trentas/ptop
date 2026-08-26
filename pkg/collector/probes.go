package collector

import "sort"

// What became of each collector, and why that has to leave the process.
//
// Sources (set.go) already records where a subsystem's data came from, but it
// says "" for every subsystem that produced none — and there are three unrelated
// reasons for that: the operator switched the probe off, the probe was asked for
// and failed to attach, or the platform has no such source at all. They call for
// opposite reactions. A disabled probe is a knob someone can turn back on; a
// failed one is a broken deployment; only the target genuinely not doing the
// thing is a finding.
//
// A consumer reading the event stream cannot tell them apart, because all three
// look the same on the wire: a category that never appears. That is what
// ProbeStatus exists to say out loud, and why it is reported in the subscription
// handshake next to the scope (#112) — a probe set is as much a part of what was
// observed as the pid or the cgroup is.

// ProbeState is the outcome of one collector for one target.
type ProbeState string

const (
	// ProbeActive: attached, and producing events.
	ProbeActive ProbeState = "active"
	// ProbeDisabled: not asked for — --disable named it, --no-ebpf turned off
	// the lane it needs, or it is opt-in and was not opted into.
	ProbeDisabled ProbeState = "disabled"
	// ProbeFailed: asked for and could not attach. The target is instrumented
	// less than requested, and after the fact only this says so.
	ProbeFailed ProbeState = "failed"
	// ProbeUnsupported: cannot exist here — this build embeds no eBPF, the
	// platform has no such source, or the scope structurally excludes it.
	ProbeUnsupported ProbeState = "unsupported"
)

// ProbeStatus is one subsystem's outcome, as reported to consumers.
type ProbeStatus struct {
	// Name is the subsystem, spelled as --disable accepts it (see disable.go),
	// so a status names the flag that would change it.
	Name  string
	State ProbeState
	// Source is where an ACTIVE probe's numbers come from ("eBPF", SourceProc);
	// empty otherwise. The same subsystem read through a different source is not
	// the same measurement.
	Source string
	// Detail is why a probe that is not ACTIVE is not running: the attach error,
	// or the flag that switched it off. Prose, not a key.
	Detail string
}

// probeLog accumulates one ProbeStatus per subsystem as NewSet walks them.
//
// Recording is inline rather than derived at the end because the interesting
// part — the attach error — exists only at the moment of the failure. Deriving
// the set afterwards from which collectors are nil would recover the states and
// throw away every reason.
type probeLog struct{ m map[string]ProbeStatus }

// set records st unless the probe is already active. A subsystem with a /proc
// fallback is walked twice — eBPF first, then /proc — so the eBPF failure must
// not overwrite the fallback that succeeded, nor the reverse. Active is the
// answer whenever any lane produced data.
func (l *probeLog) set(st ProbeStatus) {
	if l.m == nil {
		l.m = make(map[string]ProbeStatus)
	}
	if prev, ok := l.m[st.Name]; ok && prev.State == ProbeActive {
		return
	}
	l.m[st.Name] = st
}

func (l *probeLog) active(name, source string) {
	l.set(ProbeStatus{Name: name, State: ProbeActive, Source: source})
}

func (l *probeLog) disabled(name, why string) {
	l.set(ProbeStatus{Name: name, State: ProbeDisabled, Detail: why})
}

func (l *probeLog) unsupported(name, why string) {
	l.set(ProbeStatus{Name: name, State: ProbeUnsupported, Detail: why})
}

// failed records an attach failure — or, on a build with no eBPF programs
// embedded, the honest answer that this binary never had the probe to begin
// with. Calling that a failure would report a broken deployment on every bare
// build; it is the same distinction warnEBPFFailure makes before warning.
func (l *probeLog) failed(name string, err error, ebpfAvailable bool) {
	if !ebpfAvailable {
		l.unsupported(name, "this ptop build embeds no eBPF programs (build with -tags=ebpf)")
		return
	}
	l.set(ProbeStatus{Name: name, State: ProbeFailed, Detail: err.Error()})
}

// statuses returns every recorded subsystem, sorted by name so two captures of
// the same configuration report byte-identical probe sets.
func (l *probeLog) statuses() []ProbeStatus {
	if len(l.m) == 0 {
		return nil
	}
	out := make([]ProbeStatus, 0, len(l.m))
	for _, st := range l.m {
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ebpfOnlySubsystems have no /proc lane at all: --no-ebpf does not degrade them,
// it removes them. They are listed here rather than inferred so degraded mode
// can report them as disabled without walking collectors it never constructs.
//
// io is deliberately absent. Its per-file view is eBPF-only, but iowait% and
// throughput come from /proc and publish under the same category, so degraded
// mode still produces io events — reporting it disabled would be the same lie
// this file exists to stop telling.
var ebpfOnlySubsystems = []string{
	SubsystemSyscalls, SubsystemNetwork, SubsystemFutex,
	SubsystemHeap, SubsystemSignals, SubsystemLifecycle, SubsystemSecurity,
	SubsystemTLS,
}

// cgroupUnsupported names the subsystems a cgroup subtree structurally cannot
// have, with the reason (see Set.startCgroup, which documents each one). They
// are reported rather than omitted: a consumer must be able to tell "this scope
// cannot observe heap" from "heap was switched off", because only the second is
// something an operator can change.
var cgroupUnsupported = map[string]string{
	SubsystemMemory:    "cgroup scope: RSS comes from /proc/<pid>/statm and a subtree has no single pid",
	SubsystemThreads:   "cgroup scope: thread enumeration comes from /proc/<pid>/task and a subtree has no single pid",
	SubsystemHeap:      "cgroup scope: the allocator uprobe attaches into one process's mapped libc",
	SubsystemTLS:       "cgroup scope: the libssl uprobe attaches into one process's mapped libssl",
	SubsystemSignals:   "cgroup scope: the signal probe filters on a global pid of its own",
	SubsystemLifecycle: "cgroup scope: the exec-lineage probe filters on a global pid of its own",
	SubsystemFD:        "cgroup scope: fd enumeration comes from /proc/<pid>/fd and a subtree has no single pid",
}

// cgroupSubsystems are the ones startCgroup can run — the subtree-capable set,
// everything not in cgroupUnsupported.
var cgroupSubsystems = []string{
	SubsystemCPU, SubsystemSyscalls, SubsystemIO,
	SubsystemNetwork, SubsystemFutex, SubsystemSecurity,
}
