//go:build !linux || !ebpf

package collector

import (
	"errors"

	"github.com/trentas/ptop/pkg/symbol"
)

// Stub: builds without -tags=ebpf or on non-Linux hosts get this
// SecurityEBPFCollector that always fails Start. Security events are eBPF-only
// (no /proc fallback, never simulated), so the consumer simply has no data.

type SecurityEBPFCollector struct{}

func NewSecurityEBPFCollector(*symbol.Debuginfod) *SecurityEBPFCollector {
	return &SecurityEBPFCollector{}
}

func (*SecurityEBPFCollector) Start(pid int) error {
	return errors.New("eBPF security collector not available in this build")
}

// StartCgroup mirrors Start: cgroup targeting is an eBPF feature (#94).
func (*SecurityEBPFCollector) StartCgroup(string) error {
	return errors.New("eBPF security collector not available in this build")
}

func (*SecurityEBPFCollector) Stop() {}

func (*SecurityEBPFCollector) Subscribe() <-chan interface{} { return nil }
