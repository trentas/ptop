//go:build !linux || !ebpf

package bpf

import "errors"

// GoPauseBuckets mirrors GOPAUSE_BUCKETS in programs/gopause.bpf.c.
const GoPauseBuckets = 32

// GoPauseTotals is the cumulative pause aggregate (#175).
type GoPauseTotals struct {
	Count   uint64
	SumNs   uint64
	Buckets [GoPauseBuckets]uint64
}

// GoPauseTracer is unavailable without eBPF.
type GoPauseTracer struct{}

var errGoPauseStub = errors.New("eBPF Go pause tracer not available in this build")

// ErrNotGo mirrors the eBPF build's: a target whose executable is not a Go
// image. Declared here too so callers can test for it in either build.
var ErrNotGo = errors.New("target is not a Go binary")

func OpenGoPauseTracer(int) (*GoPauseTracer, error)     { return nil, errGoPauseStub }
func (t *GoPauseTracer) Totals() (GoPauseTotals, error) { return GoPauseTotals{}, errGoPauseStub }
func (t *GoPauseTracer) Close() error                   { return nil }
