//go:build !linux

package collector

import "errors"

// Stub: namespaces and cgroups are Linux kernel concepts with no macOS (or other
// OS) equivalent, so the execution-context collector simply doesn't start there.
// The consumer then has no ProcContext — the help overlay reports it unavailable.

type ProcContextCollector struct{}

func NewProcContextCollector() *ProcContextCollector { return &ProcContextCollector{} }

func (*ProcContextCollector) Start(pid int) error {
	return errors.New("execution context (namespace/cgroup) is Linux-only")
}

func (*ProcContextCollector) Stop() {}

func (*ProcContextCollector) Subscribe() <-chan interface{} { return nil }
