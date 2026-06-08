//go:build !linux || !ebpf

package bpf

import (
	"errors"
	"io"
)

var errTLSStub = errors.New("eBPF tls tracer not available in this build")

const tlsMaxData = 4096

const (
	TLSDirWrite uint32 = 0
	TLSDirRead  uint32 = 1
)

// TLSEventRecord mirrors the real layout so non-ebpf builds of internal/bpf
// still compile standalone (matches io_stub.go and the other tracer stubs).
type TLSEventRecord struct {
	TsNs     uint64
	TGID     uint32
	PID      uint32
	FD       int32
	Dir      uint32
	Len      int32
	Captured uint32
	Data     [tlsMaxData]byte
}

type TLSTracer struct{}

func OpenTLSTracer(int, int) (*TLSTracer, error) { return nil, errTLSStub }
func (*TLSTracer) Next() (TLSEventRecord, error) { return TLSEventRecord{}, io.EOF }
func (*TLSTracer) Close() error                  { return nil }
