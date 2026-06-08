//go:build !linux || !ebpf

package collector

import "errors"

// Stub: builds without -tags=ebpf or on non-Linux hosts get this
// TLSEBPFCollector that always fails Start. TLS payload capture is eBPF-only
// (libssl uprobes), opt-in, and never simulated.

type TLSEBPFCollector struct{}

func NewTLSEBPFCollector(maxBytes int) *TLSEBPFCollector {
	return &TLSEBPFCollector{}
}

func (*TLSEBPFCollector) Start(pid int) error {
	return errors.New("eBPF tls collector not available in this build")
}

func (*TLSEBPFCollector) Stop() {}

func (*TLSEBPFCollector) Subscribe() <-chan interface{} { return nil }
