//go:build !linux || !ebpf

package bpf

import (
	"errors"
	"io"
)

var errProcStub = errors.New("eBPF proc lifecycle tracer not available in this build")

// ProcRecord mirrors the real layout so non-ebpf builds of internal/bpf still
// compile standalone (matches signal_stub.go and the other tracer stubs).
type ProcRecord struct {
	TsNs     uint64
	Kind     uint32
	PID      int32
	PPID     int32
	Pad      uint32
	Comm     [16]byte
	Filename [128]byte
}

type ProcTracer struct{}

func OpenProcTracer(int) (*ProcTracer, error) { return nil, errProcStub }
func (*ProcTracer) Next() (ProcRecord, error) { return ProcRecord{}, io.EOF }
func (*ProcTracer) Close() error              { return nil }
