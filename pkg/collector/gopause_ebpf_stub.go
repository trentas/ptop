//go:build !linux || !ebpf

package collector

import "errors"

type GoPauseEBPFCollector struct{}

func NewGoPauseEBPFCollector() *GoPauseEBPFCollector { return &GoPauseEBPFCollector{} }
func (*GoPauseEBPFCollector) Start(int) error {
	return errors.New("eBPF Go pause collector not available in this build")
}
func (*GoPauseEBPFCollector) Stop()                         {}
func (*GoPauseEBPFCollector) Subscribe() <-chan interface{} { return nil }
