//go:build !linux || !ebpf

package bpf

import (
	"errors"
	"net"
)

var errNetStub = errors.New("eBPF network tracer not available in this build")

type NetSnapshot struct {
	Family  uint16
	SAddr   net.IP
	DAddr   net.IP
	SPort   uint16
	DPort   uint16
	State   uint32
	RTTNs   uint64
	TxBytes uint64
	RxBytes uint64
	LastNs  uint64
}

type NetConnKey struct {
	DAddr  [16]byte
	SAddr  [16]byte
	DPort  uint16
	SPort  uint16
	Family uint16
	_      uint16
}

type NetTracer struct{}

func OpenNetTracer(int) (*NetTracer, error)                       { return nil, errNetStub }
func (*NetTracer) Stats() ([]NetSnapshot, error)                   { return nil, errNetStub }
func (*NetTracer) SeedConnection(NetConnKey, uint32) error         { return errNetStub }
func (*NetTracer) Close() error                                    { return nil }
