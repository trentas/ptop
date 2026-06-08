//go:build !linux || !ebpf

package bpf

import (
	"errors"
	"io"
)

var errSignalStub = errors.New("eBPF signal tracer not available in this build")

// SignalRecord mirrors the real layout so non-ebpf builds of internal/bpf still
// compile standalone (matches io_stub.go and the other tracer stubs).
type SignalRecord struct {
	TsNs       uint64
	Signo      uint32
	SenderPID  uint32
	SenderTID  uint32
	TargetTID  uint32
	Code       int32
	Err        int32
	Result     uint32
	Group      uint32
	SenderComm [16]byte
}

type SignalTracer struct{}

func OpenSignalTracer(int) (*SignalTracer, error) { return nil, errSignalStub }
func (*SignalTracer) Next() (SignalRecord, error) { return SignalRecord{}, io.EOF }
func (*SignalTracer) Close() error                { return nil }
