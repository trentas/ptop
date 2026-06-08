//go:build !linux || !ebpf

package collector

import "errors"

// Stub: builds without -tags=ebpf or on non-Linux hosts get this
// ProcLifecycleEBPFCollector that always fails Start. Exec lineage is eBPF-only
// (no /proc fallback, never simulated), so the consumer simply has no lineage
// data.

type ProcLifecycleEBPFCollector struct{}

func NewProcLifecycleEBPFCollector() *ProcLifecycleEBPFCollector {
	return &ProcLifecycleEBPFCollector{}
}

func (*ProcLifecycleEBPFCollector) Start(pid int) error {
	return errors.New("eBPF proc lifecycle collector not available in this build")
}

func (*ProcLifecycleEBPFCollector) Stop() {}

func (*ProcLifecycleEBPFCollector) Subscribe() <-chan interface{} { return nil }
