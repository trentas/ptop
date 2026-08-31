package bpf

import (
	"errors"
	"fmt"
	"io/fs"
)

// Naming the capability in the error, instead of only the path.
//
// A uprobe that will not attach reports something like "no such file or
// directory" or "operation not permitted" against the target binary, which
// reads as a problem with the TARGET — wrong path, stripped symbol, wrong
// architecture. It is usually not. It is almost always the dynamic perf_uprobe
// PMU in perf_event_open(2), whose gate is CAP_SYS_ADMIN and which CAP_PERFMON
// does not satisfy (#117).
//
// The distinction matters more than the wording suggests. heap is the only
// axis carrying func and file:line, so losing it loses attribution entirely —
// and in a pipeline that keeps only the capture, the axis comes out as zeros
// rather than as an error, which a human then reads as "this process does not
// allocate". Whatever we can say at the moment of the failure is the last
// chance to say it.

// uprobeCapHint names the capability that most likely explains a failed uprobe
// attach, or "" when the capabilities are all in place and the fault really is
// somewhere else. It reads the current process's own capabilities, so it is
// only ever called on an error path.
func uprobeCapHint() string {
	s := GetCapStatus()
	switch {
	case s.IsRoot:
		return ""
	case !s.HasSysAdmin:
		return "this process has no CAP_SYS_ADMIN: the perf_uprobe PMU that perf_event_open(2) " +
			"creates for a uprobe is gated on it, and CAP_PERFMON does not satisfy it — run `ptop --caps`"
	case !s.HasSysPtrace:
		return "this process has no CAP_SYS_PTRACE: attaching reads the target's " +
			"/proc/<pid>/{exe,maps,map_files}, which needs ptrace-mode access when the target " +
			"belongs to another user — run `ptop --caps`"
	}
	return ""
}

// targetReadError annotates a failed read of the TARGET's /proc entry —
// /proc/<pid>/ns/pid, /proc/<pid>/exe, /proc/<pid>/maps. Measured on 7.0.0
// with every other capability granted, a root-owned target loses nine of the
// twelve collectors here, eight of them at the pid-namespace stat alone; the
// bare error says "permission denied" against a path in /proc and gives no
// hint that one capability recovers all of them.
//
// Only permission failures are annotated. The same call sites legitimately
// return ErrNotGo and plain not-found, and attaching a capability hint to
// those would send the reader somewhere there is nothing to find. The cause is
// always wrapped with %w, so errors.Is on the sentinel keeps working.
func targetReadError(what string, err error) error {
	s := GetCapStatus()
	if errors.Is(err, fs.ErrPermission) && !s.IsRoot && !s.HasSysPtrace {
		return fmt.Errorf("%s: %w (this process has no CAP_SYS_PTRACE, and reading "+
			"another user's /proc/<pid>/{ns/pid,exe,maps} is ptrace-mode access — run `ptop --caps`)", what, err)
	}
	return fmt.Errorf("%s: %w", what, err)
}

// kprobeLoadError annotates a failed load of a collection containing a
// kprobe-type program. cilium/ebpf stamps the running kernel's version into
// those at load time and reads it out of the vDSO through /proc/self/mem —
// which a setcap'd ptop cannot open, because the privilege gained at exec made
// it non-dumpable and handed its own /proc/self/* to root. What surfaces is
// "detecting kernel version: opening mem: … permission denied", naming neither
// the capability that fixes it nor the setcap that caused it (#117).
//
// UPROBE programs count: SEC("uprobe/…") loads as BPF_PROG_TYPE_KPROBE, so the
// heap and TLS collections take the same version read and fail the same way.
// That is why heap needs CAP_DAC_READ_SEARCH as well as CAP_SYS_ADMIN, and why
// granting only the latter recovers nothing.
//
// The trigger is the measured read, not the text of the error: whatever
// upstream calls the failure, an unreadable /proc/self/mem is the reason.
func kprobeLoadError(what string, err error) error {
	if s := GetCapStatus(); !s.ProcSelfMemReadable && !s.IsRoot && !s.HasDACReadSearch {
		return fmt.Errorf("%s: %w (this process cannot read its own /proc/self/mem, where the "+
			"kernel version stamped into every kprobe- and uprobe-type program is read from — a "+
			"setcap'd binary is non-dumpable and needs CAP_DAC_READ_SEARCH to read it back; "+
			"run `ptop --caps`)", what, err)
	}
	return fmt.Errorf("%s: %w", what, err)
}

// uprobeAttachError builds the error a failed uprobe attach returns, appending
// uprobeCapHint when there is one. cause may be nil, for a call site that
// aggregated several attempts and has only the verdict.
func uprobeAttachError(what string, cause error) error {
	hint := uprobeCapHint()
	switch {
	case cause != nil && hint != "":
		return fmt.Errorf("%s: %w (%s)", what, cause, hint)
	case cause != nil:
		return fmt.Errorf("%s: %w", what, cause)
	case hint != "":
		return fmt.Errorf("%s (%s)", what, hint)
	}
	return fmt.Errorf("%s", what)
}
