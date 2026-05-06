//go:build !linux || !ebpf

package collector

import "errors"

type FutexEBPFCollector struct{}

func NewFutexEBPFCollector() *FutexEBPFCollector {
	return &FutexEBPFCollector{}
}

func (c *FutexEBPFCollector) Start(pid int) error {
	return errors.New("futex eBPF not available in this build")
}

func (c *FutexEBPFCollector) Stop() {}

func (c *FutexEBPFCollector) Subscribe() <-chan interface{} {
	return nil
}
