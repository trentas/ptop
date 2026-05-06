//go:build !linux || !ebpf

package collector

import "errors"

// NetworkEBPFCollector is a no-op stub in builds without -tags=ebpf
// (non-Linux or no libbpf). Keeps the API the same so model.go can
// instantiate it without branching by OS.
type NetworkEBPFCollector struct{}

func NewNetworkEBPFCollector() *NetworkEBPFCollector {
	return &NetworkEBPFCollector{}
}

func (c *NetworkEBPFCollector) Start(pid int) error {
	return errors.New("network eBPF not available in this build")
}

func (c *NetworkEBPFCollector) Stop() {}

func (c *NetworkEBPFCollector) Subscribe() <-chan interface{} {
	return nil
}
