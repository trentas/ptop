//go:build !linux || !ebpf

package collector

import "errors"

type JVMPauseEBPFCollector struct{}

func NewJVMPauseEBPFCollector() *JVMPauseEBPFCollector { return &JVMPauseEBPFCollector{} }
func (*JVMPauseEBPFCollector) Start(int) error {
	return errors.New("eBPF JVM pause collector not available in this build")
}
func (*JVMPauseEBPFCollector) Caveat() string                { return "" }
func (*JVMPauseEBPFCollector) Stop()                         {}
func (*JVMPauseEBPFCollector) Subscribe() <-chan interface{} { return nil }
