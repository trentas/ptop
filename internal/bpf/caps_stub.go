//go:build !linux

package bpf

// CapStatus on non-Linux OSes: always indicates eBPF cannot run.
// We keep the same shape so main.go doesn't need a build tag.
type CapStatus struct {
	IsRoot       bool
	HasBPF       bool
	HasPerfmon   bool
	HasSysAdmin  bool
	HasSysPtrace bool

	KernelMajor       int
	KernelMinor       int
	UnprivBPFDisabled int
}

func GetCapStatus() CapStatus {
	return CapStatus{UnprivBPFDisabled: -1}
}

func (CapStatus) CanLoadBPF() bool         { return false }
func (CapStatus) KernelSupportsBPF() bool  { return false }

func (CapStatus) Diagnose() string {
	return "" +
		"eBPF requires Linux 5.8+. You are running on an unsupported OS.\n" +
		"\n" +
		"Use --no-ebpf to run the TUI in simulated/dev mode:\n" +
		"  ./bin/xray --pid <PID> --no-ebpf\n"
}
