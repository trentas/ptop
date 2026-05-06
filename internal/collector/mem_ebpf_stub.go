//go:build !linux || !ebpf

package collector

import "errors"

type MemEBPFCollector struct{}

func NewMemEBPFCollector() *MemEBPFCollector {
	return &MemEBPFCollector{}
}

func (c *MemEBPFCollector) Start(pid int) error {
	return errors.New("memory eBPF not available in this build")
}

func (c *MemEBPFCollector) Stop() {}

func (c *MemEBPFCollector) Subscribe() <-chan interface{} {
	return nil
}
