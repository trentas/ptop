//go:build !linux || !ebpf

package collector

import "errors"

type CPUEBPFCollector struct{}

func NewCPUEBPFCollector() *CPUEBPFCollector { return &CPUEBPFCollector{} }
func (*CPUEBPFCollector) Start(int) error {
	return errors.New("eBPF cpu sampler não disponível neste build")
}
func (*CPUEBPFCollector) Stop()                          {}
func (*CPUEBPFCollector) Subscribe() <-chan interface{}  { return nil }
