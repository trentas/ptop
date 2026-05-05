//go:build !linux || !ebpf

package bpf

import "errors"

// Stub não-Linux ou sem `-tags=ebpf`. Mesma shape da versão real.
// Permite o resto do projeto importar `internal/bpf` em macOS sem quebrar
// a compilação. Em runtime, OpenSyscallTracer falha cedo e o model cai pra
// simulação.

var errSyscallsStub = errors.New("eBPF syscalls não disponível neste build (precisa Linux + -tags=ebpf)")

type SyscallStat struct {
	Count      uint64
	TotalLatNs uint64
}

type SyscallTracer struct{}

func OpenSyscallTracer(pid int) (*SyscallTracer, error) {
	return nil, errSyscallsStub
}

func (t *SyscallTracer) Stats() (map[uint32]SyscallStat, error) {
	return nil, errSyscallsStub
}

func (t *SyscallTracer) Close() error {
	return nil
}
