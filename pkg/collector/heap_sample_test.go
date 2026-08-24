package collector

import (
	"testing"

	"github.com/trentas/ptop/internal/bpf"
)

// The zero value of SetConfig has to be the cheap configuration. Recording
// every Go allocation costs a large multiple of the TARGET's own CPU time
// (#108), so a caller that never thought about the field must not get it.
func TestHeapSampleBytesDefaultsToSampling(t *testing.T) {
	if got := heapSampleBytes(SetConfig{}); got != bpf.GoAllocDefaultSampleBytes {
		t.Errorf("zero config = %d, want the default rate %d", got, bpf.GoAllocDefaultSampleBytes)
	}
	if got := heapSampleBytes(SetConfig{HeapSampleBytes: 4096}); got != 4096 {
		t.Errorf("explicit rate = %d, want 4096", got)
	}
	// Every allocation is asked for by name, never by omission.
	if got := heapSampleBytes(SetConfig{HeapSampleBytes: HeapSampleEveryAllocation}); got != 1 {
		t.Errorf("HeapSampleEveryAllocation = %d, want 1", got)
	}
}

// sample_bytes on the wire means "the per-site split is an estimate". Recording
// every allocation is exact, so it must report 0 however userspace spelled it.
func TestSampledRateReportsExactAsZero(t *testing.T) {
	cases := []struct{ in, want uint64 }{
		{0, 0},                         // kernel default: no sampler
		{HeapSampleEveryAllocation, 0}, // one byte: every allocation, exact
		{2, 2},                         // the smallest rate that estimates
		{512 * 1024, 512 * 1024},       // the default
	}
	for _, tc := range cases {
		if got := sampledRate(tc.in); got != tc.want {
			t.Errorf("sampledRate(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
