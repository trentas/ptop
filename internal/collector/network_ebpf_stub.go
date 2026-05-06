//go:build !linux || !ebpf

package collector

import "errors"

// NetworkEBPFCollector é um stub no-op em builds sem -tags=ebpf
// (não-Linux ou sem libbpf). Mantém a API igual pra que o model.go
// possa instanciar sem branch por OS.
type NetworkEBPFCollector struct{}

func NewNetworkEBPFCollector() *NetworkEBPFCollector {
	return &NetworkEBPFCollector{}
}

func (c *NetworkEBPFCollector) Start(pid int) error {
	return errors.New("network eBPF não disponível neste build")
}

func (c *NetworkEBPFCollector) Stop() {}

func (c *NetworkEBPFCollector) Subscribe() <-chan interface{} {
	return nil
}
