//go:build !linux || !ebpf

package collector

import "errors"

type FutexEBPFCollector struct{}

func NewFutexEBPFCollector() *FutexEBPFCollector {
	return &FutexEBPFCollector{}
}

func (c *FutexEBPFCollector) Start(pid int) error {
	return errors.New("futex eBPF não disponível neste build")
}

func (c *FutexEBPFCollector) Stop() {}

func (c *FutexEBPFCollector) Subscribe() <-chan interface{} {
	return nil
}
