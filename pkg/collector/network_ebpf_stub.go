//go:build !darwin && (!linux || !ebpf)

package collector

import "errors"

// NetworkEBPFCollector is a no-op stub for builds without -tags=ebpf on
// platforms that don't have a Tier 1 substitute. macOS has its own
// real implementation in network_darwin.go.
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
