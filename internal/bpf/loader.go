//go:build linux && ebpf

package bpf

import "fmt"

// Loader gerencia o ciclo de vida de programas eBPF carregados via libbpfgo.
// Esta versão (Linux + tag `ebpf`) será preenchida pela issue #9 com a
// implementação real. Por agora retorna erro indicando que o subsystem
// ainda não está implementado.
type Loader struct{}

func NewLoader() *Loader {
	return &Loader{}
}

// LoadSyscalls carrega o programa eBPF de tracing de syscalls e attacha
// nos tracepoints raw_syscalls/sys_{enter,exit} filtrando por target_pid.
//
// Issue #9 vai implementar de fato:
//   - go:generate compila programs/syscalls.bpf.c → .o
//   - go:embed embute o .o no binário
//   - libbpfgo.NewModuleFromBuffer carrega o objeto
//   - mapeia target_pid via BPF map
//   - attacha programs em raw_syscalls:sys_enter / sys_exit
func (*Loader) LoadSyscalls(pid int) error {
	return fmt.Errorf("eBPF syscalls collector ainda não implementado (issue #9)")
}

// LoadCPU sampling via perf_event — issue #10
func (*Loader) LoadCPU(pid int) error {
	return fmt.Errorf("eBPF cpu collector ainda não implementado (issue #10)")
}

// LoadIO block tracepoints — issue #11
func (*Loader) LoadIO(pid int) error {
	return fmt.Errorf("eBPF io collector ainda não implementado (issue #11)")
}

// LoadNetwork sock tracepoints — issue #12
func (*Loader) LoadNetwork(pid int) error {
	return fmt.Errorf("eBPF network collector ainda não implementado (issue #12)")
}

// LoadSched threads + off-CPU — issue #13
func (*Loader) LoadSched(pid int) error {
	return fmt.Errorf("eBPF sched collector ainda não implementado (issue #13)")
}

// LoadMemory mmap/page_fault tracepoints — issue #14
func (*Loader) LoadMemory(pid int) error {
	return fmt.Errorf("eBPF memory collector ainda não implementado (issue #14)")
}
