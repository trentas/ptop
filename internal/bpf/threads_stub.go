//go:build !linux || !ebpf

package bpf

import "errors"

var errThreadsStub = errors.New("eBPF threads tracer not available in this build")

type ThreadsTracer struct{}

func OpenThreadsTracer(Target) (*ThreadsTracer, error) { return nil, errThreadsStub }
func (*ThreadsTracer) PruneDeadTIDs([]int) error       { return errThreadsStub }
func (*ThreadsTracer) Totals() (map[uint32]ThreadTotals, error) {
	return nil, errThreadsStub
}
func (*ThreadsTracer) Close() error { return nil }
