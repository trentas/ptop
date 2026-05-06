//go:build !linux || !ebpf

package collector

import "errors"

type ThreadsEBPFCollector struct{}

func NewThreadsEBPFCollector() *ThreadsEBPFCollector {
	return &ThreadsEBPFCollector{}
}

func (c *ThreadsEBPFCollector) Start(pid int) error {
	return errors.New("threads eBPF não disponível neste build")
}

func (c *ThreadsEBPFCollector) Stop() {}

func (c *ThreadsEBPFCollector) Subscribe() <-chan interface{} {
	return nil
}
