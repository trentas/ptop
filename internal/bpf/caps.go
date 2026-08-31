//go:build linux

package bpf

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Capability bits from uapi/linux/capability.h relevant to ptop.
//
// The set is larger than CAP_BPF + CAP_PERFMON, and the extra two are not
// obvious from any error the kernel returns — see capgates.go for what each
// one gates and why.
const (
	capDACReadSearch = 2
	capSysPtrace     = 19
	capSysAdmin      = 21
	capPerfmon       = 38
	capBPF           = 39
)

// tracefsCandidates are the mount points cilium/ebpf looks for tracefs at, in
// the order it tries them. Every tracepoint attach resolves an event id under
// <mount>/events/<group>/<name>/id, so a mount ptop cannot read is a mount
// where no tracepoint collector starts.
var tracefsCandidates = []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"}

// CapStatus describes which privileges the current process has at runtime,
// plus kernel/sysctl info that affects eBPF availability.
type CapStatus struct {
	IsRoot           bool
	HasBPF           bool
	HasPerfmon       bool
	HasSysAdmin      bool
	HasSysPtrace     bool
	HasDACReadSearch bool

	// KernelMajor and KernelMinor are parsed from uname.release.
	// Zero (=0) if the read failed.
	KernelMajor int
	KernelMinor int

	// UnprivBPFDisabled is the value of /proc/sys/kernel/unprivileged_bpf_disabled.
	// 0 = unprivileged eBPF allowed; 1/2 = blocked (default on modern distros).
	// -1 = sysctl could not be read.
	UnprivBPFDisabled int

	// FileCaps reports that this process holds capabilities it did not get
	// from being root — i.e. they came from a file capability on the binary,
	// which is exactly what the README's setcap line installs.
	FileCaps bool

	// NonDumpable is PR_GET_DUMPABLE != SUID_DUMP_USER, and it is the fact
	// that actually costs collectors. The kernel sets it at exec whenever the
	// new credentials are not a subset of the old — a setcap'd binary exec'd
	// by an ordinary user — and then task_dump_owner() hands that process's
	// own /proc/self/* to root. /proc/self/mem, mode 0600, becomes unreadable
	// to the process itself.
	//
	// It is read rather than inferred from FileCaps because it depends on the
	// exec CHAIN, not on the binary: exec'd from a shell it is set, but exec'd
	// from a parent that still holds the same capabilities (a privileged
	// launcher, `setpriv` without --clear-caps) nothing is gained, so nothing
	// is set and the same binary with the same file capabilities keeps reading
	// its own memory. Measured on 7.0.0, both ways round.
	NonDumpable bool

	// ProcSelfMemReadable is whether /proc/self/mem could be opened. This is
	// not a curiosity: cilium/ebpf reads the running kernel's version out of
	// the vDSO image through /proc/self/mem, and stamps it into every
	// kprobe-type program at load time. Unreadable here means the collectors
	// carrying a kprobe never load, whatever else is granted.
	ProcSelfMemReadable bool

	// TracefsPath is the tracefs mount found, or "" if none is mounted.
	// TracefsReadable is whether its events directory could be opened —
	// it is 0700 root:root on most distributions.
	TracefsPath     string
	TracefsReadable bool
}

// GetCapStatus returns a snapshot of the process's privileges. It never fails:
// fields that can't be determined are left zero.
func GetCapStatus() CapStatus {
	s := CapStatus{
		IsRoot:            os.Geteuid() == 0,
		UnprivBPFDisabled: -1,
	}
	s.HasBPF = hasCapability(capBPF)
	s.HasPerfmon = hasCapability(capPerfmon)
	s.HasSysAdmin = hasCapability(capSysAdmin)
	s.HasSysPtrace = hasCapability(capSysPtrace)
	s.HasDACReadSearch = hasCapability(capDACReadSearch)
	s.FileCaps = !s.IsRoot && (s.HasBPF || s.HasPerfmon || s.HasSysAdmin ||
		s.HasSysPtrace || s.HasDACReadSearch)
	if d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err == nil {
		s.NonDumpable = d != 1 // 1 == SUID_DUMP_USER
	}
	s.ProcSelfMemReadable = canOpen("/proc/self/mem")
	s.TracefsPath, s.TracefsReadable = probeTracefs()
	s.KernelMajor, s.KernelMinor = readKernelVersion()
	if data, err := os.ReadFile("/proc/sys/kernel/unprivileged_bpf_disabled"); err == nil {
		if v, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			s.UnprivBPFDisabled = v
		}
	}
	return s
}

// Diagnose returns a multi-line message explaining the process state and
// how to obtain eBPF privileges (or fall back to --no-ebpf). Empty if OK.
//
// It answers only the fatal question — can any eBPF load at all. The partial
// answer, where the load succeeds and individual collectors do not, is
// CapReport (capgates.go); Diagnose points at it rather than repeating it.
func (s CapStatus) Diagnose() string {
	if s.CanLoadBPF() && s.KernelSupportsBPF() {
		return ""
	}
	var b strings.Builder

	// Kernel issue takes priority — no point suggesting caps if kernel is old.
	if !s.KernelSupportsBPF() {
		fmt.Fprintf(&b, "Kernel %d.%d detected — ptop requires Linux 5.8+ (BTF + CAP_BPF).\n",
			s.KernelMajor, s.KernelMinor)
		fmt.Fprintln(&b, "On older kernels, use --no-ebpf (/proc-only mode).")
		return b.String()
	}

	fmt.Fprintln(&b, "eBPF not available with current privileges.")

	// Which caps are missing?
	missing := []string{}
	if !s.HasBPF {
		missing = append(missing, "CAP_BPF")
	}
	if !s.HasPerfmon {
		missing = append(missing, "CAP_PERFMON")
	}
	if len(missing) > 0 && !s.IsRoot {
		fmt.Fprintf(&b, "Missing: %s\n", strings.Join(missing, ", "))
	}

	if s.UnprivBPFDisabled > 0 && !s.IsRoot {
		fmt.Fprintln(&b, "")
		fmt.Fprintf(&b, "Warning: kernel.unprivileged_bpf_disabled=%d — unprivileged eBPF blocked.\n",
			s.UnprivBPFDisabled)
		fmt.Fprintln(&b, "To revert (temporarily): sudo sysctl kernel.unprivileged_bpf_disabled=0")
	}

	fmt.Fprintln(&b, "")
	fmt.Fprintln(&b, "Options:")
	fmt.Fprintln(&b, "  1) Run with sudo:")
	fmt.Fprintln(&b, "       sudo ./bin/ptop --pid <PID>")
	fmt.Fprintln(&b, "  2) Apply caps to the binary (one-time):")
	fmt.Fprintf(&b, "       sudo %s ./bin/ptop\n", RecommendedSetcap)
	fmt.Fprintln(&b, "     cap_bpf,cap_perfmon alone loads only part of the probe set;")
	fmt.Fprintln(&b, "     `ptop --caps` reports which collectors each capability gates.")
	fmt.Fprintln(&b, "  3) /proc-only mode (no eBPF, no privileges):")
	fmt.Fprintln(&b, "       ./bin/ptop --pid <PID> --no-ebpf")

	return b.String()
}

// hasCapability reads /proc/self/status (CapEff field) and tests the cap bit.
// Returns false on any error.
//
// This read keeps working after setcap even though it goes through the same
// root-owned /proc/self: status is world-readable (0444), where mem is 0600.
// That asymmetry is why a capability-starved ptop can still report accurately
// on its own capabilities.
func hasCapability(capBit int) bool {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		hexStr := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		eff, err := strconv.ParseUint(hexStr, 16, 64)
		if err != nil {
			return false
		}
		return eff&(uint64(1)<<uint(capBit)) != 0
	}
	return false
}

// canOpen reports whether path can be opened for reading. Opening is the test
// rather than stat-plus-arithmetic because the answer depends on capabilities,
// LSM policy and mount options at once, and only the open consults all three.
func canOpen(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// probeTracefs finds the tracefs mount and reports whether its event directory
// can be read. Not being mounted and not being readable are different problems
// with different fixes, so the path is returned alongside the verdict.
func probeTracefs() (path string, readable bool) {
	for _, candidate := range tracefsCandidates {
		var st syscall.Stat_t
		if err := syscall.Stat(candidate, &st); err != nil {
			continue
		}
		if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
			continue
		}
		return candidate, canOpen(candidate + "/events")
	}
	return "", false
}

// readKernelVersion parses "X.Y" from the start of /proc/sys/kernel/osrelease.
func readKernelVersion() (major, minor int) {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return 0, 0
	}
	s := strings.TrimSpace(string(data))
	// Format: "5.15.0-91-generic" → major=5, minor=15
	parts := strings.SplitN(s, ".", 3)
	if len(parts) < 2 {
		return 0, 0
	}
	major, _ = strconv.Atoi(parts[0])
	minor, _ = strconv.Atoi(parts[1])
	return major, minor
}
