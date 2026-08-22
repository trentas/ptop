//go:build !linux || !ebpf

package collector

import (
	"errors"

	"github.com/trentas/ptop/pkg/symbol"
)

type FutexEBPFCollector struct{}

func NewFutexEBPFCollector() *FutexEBPFCollector {
	return &FutexEBPFCollector{}
}

func (c *FutexEBPFCollector) Start(pid int) error {
	return errors.New("futex eBPF not available in this build")
}

// StartCgroup mirrors Start: cgroup targeting is an eBPF feature (#94).
func (c *FutexEBPFCollector) StartCgroup(string) error {
	return errors.New("futex eBPF not available in this build")
}

func (c *FutexEBPFCollector) Stop() {}

func (c *FutexEBPFCollector) Subscribe() <-chan interface{} {
	return nil
}

// ResolveStack / ProcessBuildID satisfy the serve.StackResolver shape so the
// headless server can hold a *FutexEBPFCollector uniformly (#89); without eBPF
// there is nothing to resolve.
func (*FutexEBPFCollector) ResolveStack(uint64) ([]symbol.Frame, bool) { return nil, false }
func (*FutexEBPFCollector) ProcessBuildID() string                     { return "" }
