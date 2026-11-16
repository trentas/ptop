//go:build !linux || !ebpf

package bpf

import "errors"

// JVMPauseTracer is unavailable without eBPF.
type JVMPauseTracer struct{}

var errJVMPauseStub = errors.New("eBPF JVM pause tracer not available in this build")

func OpenJVMPauseTracer(int) (*JVMPauseTracer, error)  { return nil, errJVMPauseStub }
func (t *JVMPauseTracer) Lanes() (safepoints, gc bool) { return false, false }
func (t *JVMPauseTracer) Caveat() string               { return "" }
func (t *JVMPauseTracer) Close() error                 { return nil }
func (t *JVMPauseTracer) Totals() (safepoints, gc PauseTotals, err error) {
	return safepoints, gc, errJVMPauseStub
}
