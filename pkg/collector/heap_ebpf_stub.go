//go:build !linux || !ebpf

package collector

import (
	"errors"

	"github.com/trentas/ptop/pkg/symbol"
)

type HeapEBPFCollector struct{}

func NewHeapEBPFCollector() *HeapEBPFCollector { return &HeapEBPFCollector{} }
func (*HeapEBPFCollector) Start(int) error {
	return errors.New("eBPF heap collector not available in this build")
}
func (*HeapEBPFCollector) Stop()                         {}
func (*HeapEBPFCollector) Subscribe() <-chan interface{} { return nil }

// ResolveStack / ProcessBuildID satisfy the serve.StackResolver shape so the
// headless server can hold a *HeapEBPFCollector uniformly; without eBPF there
// is nothing to resolve.
func (*HeapEBPFCollector) ResolveStack(uint64) ([]symbol.Frame, bool) { return nil, false }
func (*HeapEBPFCollector) ProcessBuildID() string                     { return "" }
