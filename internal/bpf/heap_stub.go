//go:build !linux || !ebpf

package bpf

import (
	"errors"
	"io"
)

var errHeapStub = errors.New("eBPF heap tracer not available in this build")

// Op codes — mirror the OP_* defines in programs/heap.bpf.c.
const (
	HeapOpMalloc  uint32 = 0
	HeapOpCalloc  uint32 = 1
	HeapOpRealloc uint32 = 2
	HeapOpFree    uint32 = 3
)

// HeapFlagLarge mirrors HEAP_FLAG_LARGE: the allocation is ≥ 128KB.
const HeapFlagLarge uint32 = 1

type HeapEvent struct {
	TsNs       uint64
	Size       uint64
	Addr       uint64
	LifetimeNs uint64
	StackID    int32
	Op         uint32
	Flags      uint32
	TGID       uint32
}

type HeapCallSiteRaw struct {
	LiveBytes     int64
	LiveCount     int64
	AllocCount    uint64
	LifetimeSumNs uint64
	LifetimeCount uint64
	LargeCount    uint64
}

type HeapLeak struct {
	Size    uint64
	StackID int32
	AgeNs   uint64
}

type HeapTracer struct{}

func OpenHeapTracer(int) (*HeapTracer, error) { return nil, errHeapStub }

func (*HeapTracer) Next() (HeapEvent, error) { return HeapEvent{}, io.EOF }
func (*HeapTracer) LiveCallSites() (map[int32]HeapCallSiteRaw, error) {
	return nil, errHeapStub
}
func (*HeapTracer) LeakScan(uint64) ([]HeapLeak, error)  { return nil, errHeapStub }
func (*HeapTracer) ResolveStack(int32) ([]uint64, error) { return nil, errHeapStub }
func (*HeapTracer) LibcRange() (uint64, uint64)          { return 0, 0 }
func (*HeapTracer) Close() error                         { return nil }
