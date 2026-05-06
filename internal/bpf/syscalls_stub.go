//go:build !linux || !ebpf

package bpf

import "errors"

// Stub for non-Linux or builds without `-tags=ebpf`. Same shape as the real
// version. Lets the rest of the project import `internal/bpf` from any host
// without breaking the build. At runtime, OpenSyscallTracer fails early and
// the model falls back to simulation.

var errSyscallsStub = errors.New("eBPF syscalls not available in this build (requires Linux + -tags=ebpf)")

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
