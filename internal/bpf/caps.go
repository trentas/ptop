//go:build linux

package bpf

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Capability bits from uapi/linux/capability.h relevant to ptop.
const (
	capBPF       = 39
	capPerfmon   = 38
	capSysAdmin  = 21
	capSysPtrace = 19
)

// CapStatus describes which privileges the current process has at runtime,
// plus kernel/sysctl info that affects eBPF availability.
type CapStatus struct {
	IsRoot       bool
	HasBPF       bool
	HasPerfmon   bool
	HasSysAdmin  bool
	HasSysPtrace bool

	// KernelMajor and KernelMinor are parsed from uname.release.
	// Zero (=0) if the read failed.
	KernelMajor int
	KernelMinor int

	// UnprivBPFDisabled is the value of /proc/sys/kernel/unprivileged_bpf_disabled.
	// 0 = unprivileged eBPF allowed; 1/2 = blocked (default on modern distros).
	// -1 = sysctl could not be read.
	UnprivBPFDisabled int
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
	s.KernelMajor, s.KernelMinor = readKernelVersion()
	if data, err := os.ReadFile("/proc/sys/kernel/unprivileged_bpf_disabled"); err == nil {
		if v, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			s.UnprivBPFDisabled = v
		}
	}
	return s
}

// CanLoadBPF is true if the process has enough privileges to load eBPF
// programs (root OR CAP_BPF + CAP_PERFMON). Doesn't consider kernel
// version — only capabilities.
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

// Diagnose returns a multi-line message explaining the process state and
// how to obtain eBPF privileges (or fall back to --no-ebpf). Empty if OK.
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
	fmt.Fprintln(&b, "       sudo setcap cap_bpf,cap_perfmon+ep ./bin/ptop")
	fmt.Fprintln(&b, "  3) /proc-only mode (no eBPF, no privileges):")
	fmt.Fprintln(&b, "       ./bin/ptop --pid <PID> --no-ebpf")

	return b.String()
}

// hasCapability reads /proc/self/status (CapEff field) and tests the cap bit.
// Returns false on any error.
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
