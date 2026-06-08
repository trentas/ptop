//go:build !linux || !ebpf

package collector

import "errors"

// Stub: builds without -tags=ebpf or on non-Linux hosts get this
// SignalEBPFCollector that always fails Start. Signals are eBPF-only (no /proc
// fallback, never simulated), so the consumer simply has no signal data.

type SignalEBPFCollector struct{}

func NewSignalEBPFCollector() *SignalEBPFCollector {
	return &SignalEBPFCollector{}
}

func (*SignalEBPFCollector) Start(pid int) error {
	return errors.New("eBPF signal collector not available in this build")
}

func (*SignalEBPFCollector) Stop() {}

func (*SignalEBPFCollector) Subscribe() <-chan interface{} { return nil }
