//go:build !linux || !ebpf

package bpf

import "errors"

var errCPUProfStub = errors.New("eBPF cpu profiler not available in this build (requires Linux + -tags=ebpf)")

type CPUProfiler struct{}

// CPUProfRate mirrors the real type so consumers compile on every platform.
type CPUProfRate struct {
	Fired uint64
	Hit   uint64
}

func OpenCPUProfiler(Target, int) (*CPUProfiler, error)   { return nil, errCPUProfStub }
func (*CPUProfiler) Samples() (map[int32]uint64, error)   { return nil, errCPUProfStub }
func (*CPUProfiler) Rate() (CPUProfRate, error)           { return CPUProfRate{}, errCPUProfStub }
func (*CPUProfiler) ResolveStack(int32) ([]uint64, error) { return nil, errCPUProfStub }
func (*CPUProfiler) RequestedHz() int                     { return 0 }
func (*CPUProfiler) NumCPU() int                          { return 0 }
func (*CPUProfiler) Close() error                         { return nil }
