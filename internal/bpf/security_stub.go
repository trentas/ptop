//go:build !linux || !ebpf

package bpf

import (
	"errors"
	"io"
)

var errSecurityStub = errors.New("eBPF security tracer not available in this build")

// SecurityRecord mirrors the real layout so non-ebpf builds of internal/bpf
// still compile standalone (matches signal_stub.go and the other tracer stubs).
type SecurityRecord struct {
	TsNs         uint64
	Addr         uint64
	Len          uint64
	Kind         uint32
	Op           uint32
	Prot         uint32
	Flags        uint32
	LsmRequested uint32
	LsmDenied    uint32
	LsmAudited   uint32
	StackID      int32
}

type SecurityTracer struct{}

func OpenSecurityTracer(int) (*SecurityTracer, error) { return nil, errSecurityStub }

func (*SecurityTracer) Next() (SecurityRecord, error) { return SecurityRecord{}, io.EOF }

func (*SecurityTracer) ResolveStack(int32) ([]uint64, error) { return nil, nil }

func (*SecurityTracer) Close() error { return nil }
