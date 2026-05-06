//go:build !linux || !ebpf

package bpf

import "errors"

var errCPUStub = errors.New("eBPF cpu sampler not available in this build (requires Linux + -tags=ebpf)")

type CPUTracer struct{}

const SampleFreq = 100

func OpenCPUTracer(int) (*CPUTracer, error) { return nil, errCPUStub }
func (*CPUTracer) SampleCount() (uint64, error) { return 0, errCPUStub }
func (*CPUTracer) NumCPU() int                  { return 0 }
func (*CPUTracer) Close() error                 { return nil }
