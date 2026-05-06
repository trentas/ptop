//go:build !linux || !ebpf

package bpf

import "errors"

var errFutexStub = errors.New("eBPF futex tracer not available in this build")

type FutexStat struct {
	WaitCount   uint64
	WakeCount   uint64
	LatSumNs    uint64
	LatCount    uint64
	LastWaitTID uint32
	LastWakeTID uint32
}

type FutexTracer struct{}

func OpenFutexTracer(int) (*FutexTracer, error) { return nil, errFutexStub }
func (*FutexTracer) Stats() (map[uint64]FutexStat, error) {
	return nil, errFutexStub
}
func (*FutexTracer) Close() error { return nil }
