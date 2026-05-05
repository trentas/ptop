//go:build !linux

package bpf

// CapStatus em OSes não-Linux: sempre indica que eBPF não pode rodar.
// Mantemos a mesma shape pra que main.go não precise de build tag.
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
		"eBPF requer Linux 5.8+. Você está rodando em OS não suportado.\n" +
		"\n" +
		"Use --no-ebpf pra rodar a TUI em modo simulado/dev:\n" +
		"  ./bin/xray --pid <PID> --no-ebpf\n"
}
