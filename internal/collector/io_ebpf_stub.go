//go:build !linux || !ebpf

package collector

import "errors"

type IOEBPFCollector struct{}
type IOEBPFSnapshot struct {
	TopFiles []IOFileStats
	Buckets  []LatencyBucket
}

func NewIOEBPFCollector() *IOEBPFCollector { return &IOEBPFCollector{} }
func (*IOEBPFCollector) Start(int) error {
	return errors.New("eBPF io collector não disponível neste build")
}
func (*IOEBPFCollector) Stop()                          {}
func (*IOEBPFCollector) Subscribe() <-chan interface{}  { return nil }
