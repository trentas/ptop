//go:build !linux || !ebpf

package collector

import "errors"

type HeapEBPFCollector struct{}

func NewHeapEBPFCollector() *HeapEBPFCollector { return &HeapEBPFCollector{} }
func (*HeapEBPFCollector) Start(int) error {
	return errors.New("eBPF heap collector not available in this build")
}
func (*HeapEBPFCollector) Stop()                         {}
func (*HeapEBPFCollector) Subscribe() <-chan interface{} { return nil }
