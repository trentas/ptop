package main

import (
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

func stat(name string, rt time.Duration, count uint64) progStat {
	return progStat{name: name, typ: "TracePoint", runtime: rt, count: count}
}

func TestDiffSubtractsCumulativeCounters(t *testing.T) {
	before := map[ebpf.ProgramID]progStat{1: stat("a", 1000, 10)}
	after := map[ebpf.ProgramID]progStat{1: stat("a", 3000, 30)}
	got := diff(before, after, 1)
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1", len(got))
	}
	if got[0].runtime != 2000 || got[0].count != 20 {
		t.Errorf("delta = %v/%d, want 2000/20", got[0].runtime, got[0].count)
	}
}

// A program that appeared or vanished mid-window has no comparable pair. It is
// dropped rather than reported, because its counter covers an unknown fraction
// of the window and would read as a cheap probe.
func TestDiffDropsProgramsWithoutBothEndpoints(t *testing.T) {
	before := map[ebpf.ProgramID]progStat{1: stat("a", 1000, 10)}
	after := map[ebpf.ProgramID]progStat{
		1: stat("a", 2000, 20),
		2: stat("appeared", 9999, 999),
	}
	got := diff(before, after, 1)
	if len(got) != 1 || got[0].name != "a" {
		t.Fatalf("a program with no `before` must be dropped, got %+v", got)
	}
}

// A kernel program id is reused after the program is unloaded. A counter that
// went BACKWARDS is that, not a negative cost — and subtracting it would
// produce a huge unsigned run count.
func TestDiffDropsReusedIDs(t *testing.T) {
	before := map[ebpf.ProgramID]progStat{1: stat("old", 5000, 500)}
	after := map[ebpf.ProgramID]progStat{1: stat("new", 10, 1)}
	if got := diff(before, after, 1); len(got) != 0 {
		t.Errorf("a counter that went backwards is a reused id, got %+v", got)
	}
}

func TestDiffHonoursMinRuns(t *testing.T) {
	before := map[ebpf.ProgramID]progStat{1: stat("busy", 0, 0), 2: stat("idle", 0, 0)}
	after := map[ebpf.ProgramID]progStat{1: stat("busy", 1000, 100), 2: stat("idle", 5, 1)}
	got := diff(before, after, 10)
	if len(got) != 1 || got[0].name != "busy" {
		t.Errorf("min-runs should drop the idle program, got %+v", got)
	}
}

func TestDiffSortsByCostDescending(t *testing.T) {
	before := map[ebpf.ProgramID]progStat{1: stat("cheap", 0, 0), 2: stat("dear", 0, 0)}
	after := map[ebpf.ProgramID]progStat{1: stat("cheap", 10, 1), 2: stat("dear", 1000, 1)}
	got := diff(before, after, 1)
	if got[0].name != "dear" {
		t.Errorf("most expensive program should sort first, got %+v", got)
	}
}

// The share is of ONE core, not of the machine. Dividing by the core count
// would make an identical probe look cheaper on a bigger host.
func TestCoreShareIsPerCoreNotPerMachine(t *testing.T) {
	// 300ms of program time in a 30s window is 1% of one core.
	if got := coreShare(300*time.Millisecond, 30*time.Second); got < 0.999 || got > 1.001 {
		t.Errorf("coreShare = %v, want 1", got)
	}
	if got := coreShare(time.Second, 0); got != 0 {
		t.Errorf("no window means no measurement, got %v", got)
	}
}
