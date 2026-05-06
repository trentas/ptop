//go:build !linux || !ebpf

package bpf

import (
	"errors"
	"net"
)

var errNetStub = errors.New("eBPF network tracer não disponível neste build")

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

type NetTracer struct{}

func OpenNetTracer(int) (*NetTracer, error)       { return nil, errNetStub }
func (*NetTracer) Stats() ([]NetSnapshot, error)  { return nil, errNetStub }
func (*NetTracer) Close() error                   { return nil }
