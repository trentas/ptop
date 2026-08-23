package main

import (
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMedian(t *testing.T) {
	cases := []struct {
		in   []float64
		want float64
	}{
		{nil, 0},
		{[]float64{4}, 4},
		{[]float64{3, 1, 2}, 2},
		{[]float64{4, 1, 3, 2}, 2.5},
		// The reason the median is used at all: one descheduled run must not
		// move the answer.
		{[]float64{1.0, 1.02, 1.01, 0.99, 30.0}, 1.01},
	}
	for _, c := range cases {
		if got := median(c.in); math.Abs(got-c.want) > 1e-9 {
			t.Errorf("median(%v) = %v, want %v", c.in, got, c.want)
		}
	}
	// The input must not be reordered: the caller keeps it for the raw dump.
	in := []float64{3, 1, 2}
	_ = median(in)
	if !reflect.DeepEqual(in, []float64{3, 1, 2}) {
		t.Errorf("median reordered its input: %v", in)
	}
}

func TestCellSpread(t *testing.T) {
	c := cell{nsPerIter: 100, runs: []float64{90, 100, 110}}
	if got := c.spread(); math.Abs(got-0.2) > 1e-9 {
		t.Errorf("spread = %v, want 0.2", got)
	}
	if got := (cell{}).spread(); got != 0 {
		t.Errorf("empty cell spread = %v, want 0", got)
	}
	// A cell with no measurement must not divide by zero into an Inf that
	// then renders as a plausible-looking table entry.
	if got := (cell{runs: []float64{1, 2}}).spread(); got != 0 {
		t.Errorf("zero-metric spread = %v, want 0", got)
	}
}

func TestParseInts(t *testing.T) {
	got, err := parseInts(" 64, 640 ,6400 ")
	if err != nil || !reflect.DeepEqual(got, []int{64, 640, 6400}) {
		t.Errorf("= %v, %v", got, err)
	}
	for _, bad := range []string{"", "  ", "64,x", "64,-1", ","} {
		if _, err := parseInts(bad); err == nil {
			t.Errorf("parseInts(%q) accepted a bad sweep", bad)
		}
	}
}

// processCPUSeconds parses /proc/<pid>/stat positionally, and the comm field
// can contain spaces and parentheses — a process named "(evil) x" would shift
// every field after it if the parse split naively.
func TestProcessCPUSecondsOnSelf(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no procfs")
	}
	// Burn CPU first: utime/stime are accounted in 10ms ticks, and a test
	// binary that has done nothing genuinely reads 0 — which would make this
	// assert nothing rather than assert the parse.
	before := processCPUSeconds(os.Getpid())
	deadline := time.Now().Add(120 * time.Millisecond)
	var sink uint64
	for time.Now().Before(deadline) {
		for i := 0; i < 100000; i++ {
			sink = sink*2654435761 + 1
		}
	}
	_ = sink
	after := processCPUSeconds(os.Getpid())
	if after <= before {
		t.Errorf("processCPUSeconds did not advance across ~120ms of CPU: %v -> %v", before, after)
	}
	if got := processCPUSeconds(-1); got != 0 {
		t.Errorf("processCPUSeconds(-1) = %v, want 0 for a missing process", got)
	}
}

// The first configuration is the baseline every other cell is divided by; if
// it ever stopped being the un-instrumented one, every number in the table
// would be wrong in a way nothing else would catch.
func TestConfigsDecomposeTheCost(t *testing.T) {
	// The table is only a decomposition if the three instrumented arms are
	// "everything", "everything but heap" and "heap alone". Losing one of them
	// turns the result back into a single unactionable number.
	var all, noHeap, heapOnly bool
	for _, c := range configs[1:] {
		switch {
		case c.disable == "":
			all = true
		case c.disable == "heap":
			noHeap = true
		default:
			heapOnly = true
			if containsWord(c.disable, "heap") {
				t.Errorf("the heap-only arm disables heap: %q", c.disable)
			}
		}
	}
	if !all || !noHeap || !heapOnly {
		t.Errorf("configs do not decompose the cost: all=%v noHeap=%v heapOnly=%v", all, noHeap, heapOnly)
	}
}

func TestFirstConfigIsTheBaseline(t *testing.T) {
	if configs[0].ptop {
		t.Errorf("configs[0] = %+v, want the no-ptop baseline", configs[0])
	}
	for _, c := range configs[1:] {
		if !c.ptop {
			t.Errorf("config %q does not run ptop but is not the baseline", c.name)
		}
	}
}

func TestRateLabel(t *testing.T) {
	cases := []struct {
		pt   sweepPoint
		cell cell
		want string
	}{
		{sweepPoint{compute: 64, allocs: 0}, cell{allocsPerSec: 0}, "0 (no allocations)"},
		{sweepPoint{compute: 64, allocs: 1}, cell{allocsPerSec: 14_400_000}, "14.4M/s"},
		{sweepPoint{compute: 6400, allocs: 1}, cell{allocsPerSec: 110_000}, "110k/s"},
		{sweepPoint{compute: 64000, allocs: 1}, cell{allocsPerSec: 900}, "900/s"},
	}
	for _, c := range cases {
		if got := rateLabel(c.pt, c.cell); got != c.want {
			t.Errorf("rateLabel(%+v) = %q, want %q", c.pt, got, c.want)
		}
	}
}

// containsWord reports whether a comma-separated list contains the exact item.
func containsWord(list, item string) bool {
	for _, part := range strings.Split(list, ",") {
		if strings.TrimSpace(part) == item {
			return true
		}
	}
	return false
}
