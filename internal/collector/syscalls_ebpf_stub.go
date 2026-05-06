//go:build !linux || !ebpf

package collector

import "errors"

// Stub: builds without -tags=ebpf or on non-Linux hosts get this
// SyscallsEBPFCollector that always fails Start. Model handles this by
// falling back to simulation.

type SyscallsEBPFCollector struct{}

func NewSyscallsEBPFCollector() *SyscallsEBPFCollector {
	return &SyscallsEBPFCollector{}
}

func (*SyscallsEBPFCollector) Start(pid int) error {
	return errors.New("eBPF syscalls not available in this build")
}

func (*SyscallsEBPFCollector) Stop() {}

func (*SyscallsEBPFCollector) Subscribe() <-chan interface{} {
	return nil
}
