//go:build !linux || !ebpf

package collector

import "errors"

// Stub: builds sem -tags=ebpf ou em macOS/Windows recebem este SyscallsEBPFCollector
// que sempre falha em Start. Model trata isso fazendo fallback pra simulação.

type SyscallsEBPFCollector struct{}

func NewSyscallsEBPFCollector() *SyscallsEBPFCollector {
	return &SyscallsEBPFCollector{}
}

func (*SyscallsEBPFCollector) Start(pid int) error {
	return errors.New("eBPF syscalls não disponível neste build")
}

func (*SyscallsEBPFCollector) Stop() {}

func (*SyscallsEBPFCollector) Subscribe() <-chan interface{} {
	return nil
}
