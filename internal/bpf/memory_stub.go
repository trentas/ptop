//go:build !linux || !ebpf

package bpf

import "errors"

var errMemStub = errors.New("eBPF memory tracer não disponível neste build")

type MemCounters struct {
	PageFaults  uint64
	MmapCount   uint64
	MunmapCount uint64
	BrkCount    uint64
}

type MemoryTracer struct{}

func OpenMemoryTracer(int) (*MemoryTracer, error)   { return nil, errMemStub }
func (*MemoryTracer) Stats() (MemCounters, error)   { return MemCounters{}, errMemStub }
func (*MemoryTracer) Close() error                  { return nil }
