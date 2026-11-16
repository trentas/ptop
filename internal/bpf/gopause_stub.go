//go:build !linux || !ebpf

package bpf

import "errors"

// GoPauseTracer is unavailable without eBPF.
type GoPauseTracer struct{}

var errGoPauseStub = errors.New("eBPF Go pause tracer not available in this build")

// ErrNotGo mirrors the eBPF build's: a target whose executable is not a Go
// image. Declared here too so callers can test for it in either build.
var ErrNotGo = errors.New("target is not a Go binary")

func OpenGoPauseTracer(int) (*GoPauseTracer, error)   { return nil, errGoPauseStub }
func (t *GoPauseTracer) Totals() (PauseTotals, error) { return PauseTotals{}, errGoPauseStub }
func (t *GoPauseTracer) Close() error                 { return nil }
