package bpf

import "errors"

// A runtime's stop-the-world pauses, as the gopause (#175) and jvmpause (#189)
// programs aggregate them. Build-tag-free: the collectors read these in both
// builds.

// PauseBuckets is the histogram width: bucket i counts the pauses of
// [2^i, 2^(i+1)) µs, bucket 0 also those under 1 µs, the last everything
// longer. Mirrors GOPAUSE_BUCKETS and JVMPAUSE_BUCKETS in programs/.
const PauseBuckets = 32

// PauseTotals is the cumulative pause aggregate since a tracer attached.
// Mirrors struct gopause_totals and struct jvmpause_totals.
type PauseTotals struct {
	Count   uint64
	SumNs   uint64
	Buckets [PauseBuckets]uint64
}

// ErrNotJVM is a target with no HotSpot libjvm.so mapped: a JVM pause axis is
// unsupported there, never an empty one that reads as "no pause" (#189).
var ErrNotJVM = errors.New("target is not a JVM (no libjvm.so mapped)")
