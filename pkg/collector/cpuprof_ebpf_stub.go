//go:build !linux || !ebpf

package collector

import (
	"errors"

	"github.com/trentas/ptop/pkg/symbol"
)

type CPUProfEBPFCollector struct{}

func NewCPUProfEBPFCollector(int, *symbol.Debuginfod) *CPUProfEBPFCollector {
	return &CPUProfEBPFCollector{}
}
func (*CPUProfEBPFCollector) Start(int) error {
	return errors.New("eBPF cpu attribution collector not available in this build")
}
func (*CPUProfEBPFCollector) Stop()                         {}
func (*CPUProfEBPFCollector) Subscribe() <-chan interface{} { return nil }

// ResolveStack / ProcessBuildID satisfy the serve.StackResolver shape so the
// headless server can hold a *CPUProfEBPFCollector uniformly; without eBPF
// there is nothing to resolve.
func (*CPUProfEBPFCollector) ResolveStack(uint64) ([]symbol.Frame, bool) { return nil, false }
func (*CPUProfEBPFCollector) ProcessBuildID() string                     { return "" }
