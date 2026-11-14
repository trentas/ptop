//go:build !linux || !ebpf

package bpf

import (
	"errors"
	"io"
)

var errIOStub = errors.New("eBPF io tracer not available in this build")

const (
	IOOpRead  uint32 = 0
	IOOpWrite uint32 = 1
	IOOpOpen  uint32 = 2
)

type IOEvent struct {
	TsNs  uint64
	LatNs uint64
	Bytes uint64
	Ino   uint64
	FD    uint32
	Op    uint32
	TGID  uint32
	Dfd   int32
	Path  string
}

type IOTracer struct{}

func OpenIOTracer(Target) (*IOTracer, error) { return nil, errIOStub }
func (*IOTracer) Next() (IOEvent, error)     { return IOEvent{}, io.EOF }
func (*IOTracer) Close() error               { return nil }
