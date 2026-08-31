package bpf

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
)

// Which capabilities ptop actually needs, and what each one buys.
//
// `setcap cap_bpf,cap_perfmon+ep` — the line this README taught for two years —
// loads most of the probe set and silently drops the rest (#117). It is not a
// small remainder: it is the heap axis, the only one carrying func and
// file:line, plus the two collectors whose programs contain a kprobe. Worse,
// the failure is invisible downstream. A capture taken that way is
// well-formed; the dead axes publish as zeros, and zero is a measurement — it
// asserts the process did not allocate.
//
// Three mechanisms decide it, and only the first is about a capability in the
// obvious way:
//
//   - A UPROBE is created through the dynamic perf_uprobe PMU in
//     perf_event_open(2), whose gate is CAP_SYS_ADMIN. CAP_PERFMON does not
//     satisfy it. Both heap lanes (libc malloc, Go runtime.mallocgc) and the
//     TLS lane attach that way, so without it they do not.
//
//   - A KPROBE program is loaded with the running kernel's version stamped
//     into it, and cilium/ebpf reads that version out of the vDSO image
//     through /proc/self/mem (internal/vdso.go). ptop's two collectors whose
//     object files contain a SEC("kprobe/...") — memory and network — fail to
//     LOAD when that read fails, before any attach is attempted.
//
//   - A TRACEPOINT attach resolves its numeric event id by reading
//     <tracefs>/events/<group>/<name>/id, so an unreadable tracefs takes out
//     every tracepoint collector at once.
//
// And here is the part that catches people: the setcap the README recommended
// is itself what breaks the last two. A binary that gains privilege from a
// file capability becomes non-dumpable, and a non-dumpable process's own
// /proc/self/* is reassigned to root — so ptop, running as uid 1000, can no
// longer read its own /proc/self/mem. Add tracefs being 0700 root:root on most
// distributions and the mechanism recommended for NOT needing root is the one
// that needs CAP_DAC_READ_SEARCH to undo itself.
//
// So the gates are measured, not assumed: ProbeTracefs and the /proc/self/mem
// open in GetCapStatus ask the kernel rather than reasoning from cap bits,
// because AppArmor, mount options and file modes all get a vote and only the
// open consults all of them.

// RecommendedSetcap is the setcap invocation granting ptop's whole probe set.
// It is one string so the README, Diagnose and CapReport cannot drift apart.
const RecommendedSetcap = "setcap cap_bpf,cap_perfmon,cap_sys_admin,cap_dac_read_search,cap_sys_ptrace+ep"

// CanLoadBPF is true if the process has enough privileges to load eBPF
// programs (root OR CAP_BPF + CAP_PERFMON). Doesn't consider kernel
// version — only capabilities.
//
// It lives here, outside the build tags, because it is arithmetic on the
// struct and nothing else: the same fields have to yield the same answer
// wherever the tests run.
func (s CapStatus) CanLoadBPF() bool {
	return s.IsRoot || (s.HasBPF && s.HasPerfmon)
}

// KernelSupportsBPF is true if kernel >= 5.8 (BTF + ring buffer + CAP_BPF).
// Earlier versions partially work but ptop assumes 5.8+.
func (s CapStatus) KernelSupportsBPF() bool {
	if s.KernelMajor == 0 {
		return true // unknown; let the load fail with a more specific error
	}
	if s.KernelMajor > 5 {
		return true
	}
	return s.KernelMajor == 5 && s.KernelMinor >= 8
}

// CapGate is one capability, whether this process holds it, and what stops
// working without it.
type CapGate struct {
	// Cap is the kernel's name ("CAP_SYS_ADMIN"); Token is the setcap
	// spelling ("cap_sys_admin"), so a report names the fix as well as the gap.
	Cap   string
	Token string
	Held  bool
	// Fatal marks a capability without which nothing attaches at all. Those
	// are Diagnose's business — it refuses to start rather than reporting a
	// probe set that would be empty.
	Fatal bool
	// Subsystems are the collectors that stop working without this capability,
	// spelled the way --disable spells them so a report names the flag that
	// would change it. Empty for a Fatal gate: it gates all of them.
	//
	// They are literals here rather than references to pkg/collector, which
	// imports this package and cannot be imported back. TestCapGateSubsystems
	// there asserts every name spelled here is one collector knows.
	Subsystems []string
	// Why is the mechanism, in one sentence — never just "permission denied".
	Why string
	// Conditional is when the gate actually bites, for a capability that is
	// not always needed ("" = always). Outlook cannot fold these in: it is
	// asked before a target exists, and the condition is a fact about the
	// target, not about ptop.
	Conditional string
}

// allEBPFSubsystems is every collector with an eBPF lane. A capability that
// gates the pid filter gates all of them, and listing them by hand would rot.
func allEBPFSubsystems() []string {
	out := make([]string, 0, len(ebpfCollectors))
	for _, c := range ebpfCollectors {
		out = append(out, c.name)
	}
	sort.Strings(out)
	return out
}

// Gates reports every capability ptop's probe set depends on, in the order a
// reader should think about them: the fatal ones first, then the ones that
// decide how much of the set runs.
func (s CapStatus) Gates() []CapGate {
	root := s.IsRoot
	return []CapGate{
		{
			Cap: "CAP_BPF", Token: "cap_bpf", Held: root || s.HasBPF, Fatal: true,
			Why: "loads BPF programs and creates maps (bpf(2)); without it no probe of any kind attaches",
		},
		{
			Cap: "CAP_PERFMON", Token: "cap_perfmon", Held: root || s.HasPerfmon, Fatal: true,
			Why: "opens the perf events tracepoints and kprobes attach to, and permits the in-kernel reads the programs do",
		},
		{
			Cap: "CAP_SYS_ADMIN", Token: "cap_sys_admin", Held: root || s.HasSysAdmin,
			Subsystems: []string{"heap", "tls"},
			Why:        "creating the dynamic perf_uprobe PMU in perf_event_open(2) is gated on CAP_SYS_ADMIN, which CAP_PERFMON does not satisfy; heap is the only axis carrying func and file:line",
		},
		{
			Cap: "CAP_DAC_READ_SEARCH", Token: "cap_dac_read_search", Held: root || s.HasDACReadSearch,
			Subsystems: allEBPFSubsystems(),
			Why:        "a setcap'd ptop is non-dumpable, so its own /proc/self/mem is root-owned — and that is where cilium/ebpf reads the kernel version stamped into every kprobe- AND uprobe-type program; tracefs, where every tracepoint reads its event id, is 0700 root:root besides. Between the two it reaches every collector",
		},
		{
			Cap: "CAP_SYS_PTRACE", Token: "cap_sys_ptrace", Held: root || s.HasSysPtrace,
			Subsystems:  allEBPFSubsystems(),
			Why:         "pid-mode targeting stats /proc/<pid>/ns/pid to resolve the target's pid namespace (bpf.resolvePIDTarget), and the uprobe and symbolization paths read /proc/<pid>/{exe,maps,map_files,root} besides — all ptrace-mode access, so against another user's process the whole set fails, not just heap",
			Conditional: "when the target process belongs to another user",
		},
	}
}

// attachMechanism is how a collector's programs reach the kernel. It is what
// decides which capability gates the collector, so it is recorded per
// collector rather than re-derived from a capability list.
type attachMechanism uint8

const (
	attachTracepoint attachMechanism = 1 << iota
	attachKprobe
	attachUprobe
)

// ebpfCollectors is every collector that attaches something, with how it
// attaches and whether a /proc lane keeps the subsystem publishing when the
// eBPF one cannot start. Kept in step with internal/bpf/*.go by
// TestEBPFCollectorsMatchPrograms, which reads the .bpf.c sources back.
var ebpfCollectors = []struct {
	name         string
	how          attachMechanism
	procFallback bool
}{
	{"cpu", attachTracepoint, true},
	{"threads", attachTracepoint, true},
	{"memory", attachTracepoint | attachKprobe, true},
	{"io", attachTracepoint, true},
	{"network", attachTracepoint | attachKprobe, false},
	{"syscalls", attachTracepoint, false},
	{"futex", attachTracepoint, false},
	{"security", attachTracepoint, false},
	{"lifecycle", attachTracepoint, false},
	{"signals", attachTracepoint, false},
	{"heap", attachUprobe, false},
	{"tls", attachUprobe, false},
}

// CollectorOutlook is what one subsystem is expected to do with the privileges
// this process actually holds — decided BEFORE anything attaches, which is the
// whole point: after the fact it is indistinguishable from a quiet target.
type CollectorOutlook struct {
	// Subsystem, spelled as --disable spells it.
	Subsystem string
	// WillRun is whether the eBPF lane is expected to start.
	WillRun bool
	// Degraded marks a blocked eBPF lane that still has a /proc reader behind
	// it: the subsystem keeps publishing, less richly. Meaningless if WillRun.
	Degraded bool
	// Blocker is what stops it — a capability name, or the read that failed.
	// Empty if WillRun.
	Blocker string
}

// Outlook predicts, from capabilities alone, which collectors will run. It
// never attaches anything, so it is safe to call before a target is chosen and
// it is what --caps prints.
//
// It is deliberately a prediction and not a result: Set.Probes() reports what
// actually happened, but only once a target exists and the tracers have tried.
// An operator provisioning a host needs the answer before that.
func (s CapStatus) Outlook() []CollectorOutlook { return outlook(s, Available) }

// outlook takes ebpfEmbedded rather than reading the Available const so the
// table can be exercised in both shapes from a single build — including on a
// developer's macOS, where Available is false and every verdict would
// otherwise be the same one.
func outlook(s CapStatus, ebpfEmbedded bool) []CollectorOutlook {
	out := make([]CollectorOutlook, 0, len(ebpfCollectors))
	for _, c := range ebpfCollectors {
		o := CollectorOutlook{Subsystem: c.name, WillRun: true}
		switch {
		case !ebpfEmbedded:
			o.WillRun, o.Blocker = false, "this ptop build embeds no eBPF programs (build with -tags=ebpf)"
		case !s.KernelSupportsBPF():
			o.WillRun, o.Blocker = false, fmt.Sprintf("kernel %d.%d is below the 5.8 minimum", s.KernelMajor, s.KernelMinor)
		case !s.CanLoadBPF():
			o.WillRun, o.Blocker = false, "CAP_BPF + CAP_PERFMON"
		// Load comes before attach, so the kernel-version read is reported
		// ahead of the uprobe PMU. SEC("uprobe/…") loads as
		// BPF_PROG_TYPE_KPROBE, which is why the uprobe lanes are on this
		// branch at all — granting CAP_SYS_ADMIN without CAP_DAC_READ_SEARCH
		// recovers nothing.
		case c.how&(attachKprobe|attachUprobe) != 0 && !s.ProcSelfMemReadable:
			o.WillRun, o.Blocker = false, "/proc/self/mem unreadable — CAP_DAC_READ_SEARCH (kprobe- and uprobe-type programs are loaded with the kernel version read from it)"
		case c.how&attachUprobe != 0 && !s.IsRoot && !s.HasSysAdmin:
			o.WillRun, o.Blocker = false, "CAP_SYS_ADMIN (uprobe PMU in perf_event_open)"
		case c.how&attachTracepoint != 0 && !s.TracefsReadable:
			o.WillRun, o.Blocker = false, tracefsBlocker(s)
		}
		o.Degraded = !o.WillRun && c.procFallback
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Subsystem < out[j].Subsystem })
	return out
}

// tracefsBlocker distinguishes tracefs not being mounted from ptop not being
// allowed to read it. They look identical in an attach error and have
// completely different fixes — mount it, versus grant a capability.
func tracefsBlocker(s CapStatus) string {
	if s.TracefsPath == "" {
		return "tracefs is not mounted (mount -t tracefs none /sys/kernel/tracing) — tracepoint event ids are read from it"
	}
	return fmt.Sprintf("%s unreadable — CAP_DAC_READ_SEARCH (it is 0700 root:root; tracepoint event ids are read from it)", s.TracefsPath)
}

// BlockedCollectors names the subsystems Outlook expects not to run, sorted.
func (s CapStatus) BlockedCollectors() []string { return blockedCollectors(s, Available) }

func blockedCollectors(s CapStatus, ebpfEmbedded bool) []string {
	var out []string
	for _, o := range outlook(s, ebpfEmbedded) {
		if !o.WillRun {
			out = append(out, o.Subsystem)
		}
	}
	return out
}

// StartupAdvisory is the one paragraph worth printing on every run whose probe
// set is short of what the binary can do. Empty when nothing is blocked, or
// when nothing could have run anyway (no eBPF embedded, kernel too old, no
// CAP_BPF) — those already have their own, louder message.
//
// It exists because the alternative is finding out from the shape of the data,
// and the shape of the data does not distinguish a collector that never
// attached from a target that never did the thing.
//
// notAsked names the subsystems the operator has already switched off
// (--disable, or an opt-in like tls nobody opted into). A capability that
// blocks something nobody wanted is not news, and a warning that cries about
// it every run is one nobody reads by the time it matters.
func (s CapStatus) StartupAdvisory(notAsked map[string]bool) string {
	return startupAdvisory(s, Available, notAsked)
}

func startupAdvisory(s CapStatus, ebpfEmbedded bool, notAsked map[string]bool) string {
	if !ebpfEmbedded || !s.CanLoadBPF() || !s.KernelSupportsBPF() {
		return ""
	}
	var blocked []string
	for _, name := range blockedCollectors(s, ebpfEmbedded) {
		if !notAsked[name] {
			blocked = append(blocked, name)
		}
	}
	if len(blocked) == 0 {
		return ""
	}
	// Only the capabilities that gate something still being asked for.
	stillBlocked := map[string]bool{}
	for _, name := range blocked {
		stillBlocked[name] = true
	}
	var missing []string
	for _, g := range s.Gates() {
		if g.Fatal || g.Held {
			continue
		}
		for _, name := range g.Subsystems {
			if stillBlocked[name] {
				missing = append(missing, g.Cap)
				break
			}
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[ptop] ⚠ capability gap: %s will not collect.\n", strings.Join(blocked, ", "))
	if len(missing) > 0 {
		fmt.Fprintf(&b, "       Missing: %s\n", strings.Join(missing, ", "))
	}
	fmt.Fprintln(&b, "       Their axes publish as zeros, which is not the same as the target not doing it.")
	fmt.Fprintln(&b, "       `ptop --caps` explains each one; the full grant is:")
	fmt.Fprintf(&b, "         sudo %s <binary>\n", RecommendedSetcap)
	return b.String()
}

// CapReport is the full inventory --caps prints: what ptop holds, what it
// measured, and what it therefore expects each collector to do.
func (s CapStatus) CapReport() string {
	var b strings.Builder
	fmt.Fprintln(&b, "ptop capability report")
	fmt.Fprintln(&b, "")

	fmt.Fprintln(&b, "environment")
	fmt.Fprintf(&b, "  %-26s %s\n", "os", runtime.GOOS+osVerdict())
	fmt.Fprintf(&b, "  %-26s %s\n", "privilege", privilegeLabel(s))
	if s.KernelMajor != 0 {
		fmt.Fprintf(&b, "  %-26s %d.%d%s\n", "kernel", s.KernelMajor, s.KernelMinor, kernelVerdict(s))
	}
	fmt.Fprintf(&b, "  %-26s %s\n", "eBPF in this binary", yesNo(Available, "yes", "no — rebuild with -tags=ebpf"))
	if s.UnprivBPFDisabled >= 0 {
		fmt.Fprintf(&b, "  %-26s %d\n", "unprivileged_bpf_disabled", s.UnprivBPFDisabled)
	}
	fmt.Fprintln(&b, "")

	fmt.Fprintln(&b, "capabilities")
	for _, g := range s.Gates() {
		fmt.Fprintf(&b, "  %s %-21s %s\n", mark(g.Held), g.Cap, gateScope(g))
		fmt.Fprintf(&b, "      %s\n", g.Why)
	}
	fmt.Fprintln(&b, "")

	// The measured reads, separately from the cap bits. They are what actually
	// decides, and they can fail for reasons no capability explains (tracefs
	// not mounted, an LSM profile, a container without /sys).
	fmt.Fprintln(&b, "reads ptop needs, as measured now")
	fmt.Fprintf(&b, "  %s %-21s %s\n", mark(s.ProcSelfMemReadable), "/proc/self/mem",
		yesNo(s.ProcSelfMemReadable, "readable", "unreadable — kprobe programs will not load"))
	tracefs := "not mounted — no tracepoint will attach"
	if s.TracefsPath != "" {
		tracefs = yesNo(s.TracefsReadable,
			s.TracefsPath+" readable",
			s.TracefsPath+" unreadable — no tracepoint will attach")
	}
	fmt.Fprintf(&b, "  %s %-21s %s\n", mark(s.TracefsReadable), "tracefs", tracefs)
	if s.NonDumpable {
		fmt.Fprintln(&b, "      note: this process is non-dumpable — the kernel sets that at exec when the")
		fmt.Fprintln(&b, "      new credentials are not a subset of the old, which is what a setcap'd binary")
		fmt.Fprintln(&b, "      exec'd by an ordinary user does. Its own /proc/self/* then belongs to root,")
		fmt.Fprintln(&b, "      and reading it back is what CAP_DAC_READ_SEARCH is on the list for.")
	} else if s.FileCaps {
		fmt.Fprintln(&b, "      note: these capabilities came from a file capability, but this process is")
		fmt.Fprintln(&b, "      still dumpable — it gained nothing its parent did not already hold. Exec'd")
		fmt.Fprintln(&b, "      from an ordinary shell the same binary goes non-dumpable and loses these")
		fmt.Fprintln(&b, "      reads, so grant CAP_DAC_READ_SEARCH anyway rather than relying on this.")
	}
	fmt.Fprintln(&b, "")

	fmt.Fprintln(&b, "collectors, with the privileges this process holds")
	// One blocker that stops everything is a fact about the host, not about
	// twelve collectors. Repeating it twelve times buries the section that
	// matters when the answer is partial.
	if blocker, uniform := uniformBlocker(s.Outlook()); uniform {
		fmt.Fprintf(&b, "  %s none of them — %s\n", mark(false), blocker)
		fmt.Fprintln(&b, "")
		return b.String() + trailer(s)
	}
	for _, o := range s.Outlook() {
		switch {
		case o.WillRun:
			fmt.Fprintf(&b, "  %s %-12s will run\n", mark(true), o.Subsystem)
		case o.Degraded:
			fmt.Fprintf(&b, "  %s %-12s eBPF lane blocked, /proc lane still reports — %s\n", "~", o.Subsystem, o.Blocker)
		default:
			fmt.Fprintf(&b, "  %s %-12s WILL NOT COLLECT — %s\n", mark(false), o.Subsystem, o.Blocker)
		}
	}
	fmt.Fprintln(&b, "")
	fmt.Fprintln(&b, "  fd always reads /proc/<pid>/fd and attaches nothing.")
	fmt.Fprintln(&b, "  tls attaches only with --tls; heap can be switched off with --disable heap.")
	fmt.Fprint(&b, ptraceCaveat(s))
	fmt.Fprintln(&b, "")
	return b.String() + trailer(s)
}

// ptraceCaveat is the one verdict above that depends on the target rather than
// on ptop. It is printed as a caveat instead of folded into the table because
// --caps is answered before any target is named — and overstating it (marking
// every collector blocked on a host where ptop watches its owner's own
// processes) would be its own kind of wrong.
func ptraceCaveat(s CapStatus) string {
	if s.IsRoot || s.HasSysPtrace {
		return ""
	}
	return "\n" +
		"  Every verdict above assumes the target belongs to you. Without CAP_SYS_PTRACE,\n" +
		"  a target owned by another user blocks ALL of them: pid-mode targeting stats\n" +
		"  /proc/<pid>/ns/pid, and that read is ptrace-mode.\n"
}

// trailer is the fix, printed however the collector section came out.
func trailer(s CapStatus) string {
	var b strings.Builder
	fmt.Fprintln(&b, "to grant the whole set:")
	fmt.Fprintf(&b, "  sudo %s ./bin/ptop\n", RecommendedSetcap)
	fmt.Fprintln(&b, "")
	fmt.Fprintln(&b, "  CAP_SYS_ADMIN is close to root in practice, and in a container sharing the")
	fmt.Fprintln(&b, "  host pid namespace it is root. Grant it deliberately, and say so to whoever")
	fmt.Fprintln(&b, "  owns the host — or run without it and read this report to know what you lost.")
	return b.String()
}

// uniformBlocker reports the single reason nothing will run, if there is one.
func uniformBlocker(outlooks []CollectorOutlook) (string, bool) {
	if len(outlooks) == 0 {
		return "", false
	}
	first := outlooks[0].Blocker
	for _, o := range outlooks {
		if o.WillRun || o.Blocker != first {
			return "", false
		}
	}
	return first, true
}

// osVerdict says the obvious out loud on a host where no capability grant
// would help: eBPF is a Linux interface, and the macOS port is a different
// mechanism entirely (libproc + Mach, #22).
func osVerdict() string {
	if runtime.GOOS == "linux" {
		return ""
	}
	return " — eBPF is Linux-only; collectors here run through the platform port"
}

func gateScope(g CapGate) string {
	if g.Fatal {
		return "required — gates every collector"
	}
	scope := "gates: " + strings.Join(g.Subsystems, ", ")
	if len(g.Subsystems) == len(ebpfCollectors) {
		scope = "gates: every collector"
	}
	if g.Conditional != "" {
		scope += " — " + g.Conditional
	}
	return scope
}

func privilegeLabel(s CapStatus) string {
	switch {
	case s.IsRoot:
		return "root"
	case s.FileCaps && s.NonDumpable:
		return "unprivileged, with file capabilities (setcap) — non-dumpable"
	case s.FileCaps:
		return "unprivileged, with file capabilities (setcap) — still dumpable"
	}
	return "unprivileged, no capabilities"
}

func kernelVerdict(s CapStatus) string {
	if s.KernelSupportsBPF() {
		return ""
	}
	return " — below the 5.8 minimum"
}

func mark(ok bool) string {
	if ok {
		return "✓"
	}
	return "✗"
}

func yesNo(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}
