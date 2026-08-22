//go:build !linux || !ebpf

package bpf

import "errors"

var errFutexStub = errors.New("eBPF futex tracer not available in this build")

// FutexKey mirrors `struct futex_key`: the futex word plus the contention-site
// stack id (#89). See the linux+ebpf lane for the semantics.
type FutexKey struct {
	UAddr   uint64
	StackID int32
	_       uint32
}

type FutexStat struct {
	WaitCount   uint64
	WakeCount   uint64
	LatSumNs    uint64
	LatCount    uint64
	LastWaitTID uint32
	LastWakeTID uint32
}

type FutexTracer struct{}

func OpenFutexTracer(Target) (*FutexTracer, error) { return nil, errFutexStub }
func (*FutexTracer) Stats() (map[FutexKey]FutexStat, error) {
	return nil, errFutexStub
}
func (*FutexTracer) ResolveStack(int32) ([]uint64, error) { return nil, errFutexStub }
func (*FutexTracer) Close() error                         { return nil }
