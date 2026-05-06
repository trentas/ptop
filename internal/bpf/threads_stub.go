//go:build !linux || !ebpf

package bpf

import "errors"

var errThreadsStub = errors.New("eBPF threads tracer not available in this build")

type ThreadState struct {
	LastOnCpuNs   uint64
	LastOffCpuNs  uint64
	OnCpuNsTotal  uint64
	OffCpuNsTotal uint64
	CtxSwitches   uint64
}

type ThreadsTracer struct{}

func OpenThreadsTracer(int) (*ThreadsTracer, error)     { return nil, errThreadsStub }
func (*ThreadsTracer) UpdateTrackedTIDs([]int) error    { return errThreadsStub }
func (*ThreadsTracer) Stats() (map[uint32]ThreadState, error) {
	return nil, errThreadsStub
}
func (*ThreadsTracer) Close() error { return nil }
