//go:build linux

package collector

import (
	"math"
	"testing"

	"github.com/trentas/ptop/internal/bpf"
)

const sec = uint64(1e9)

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func alive(tids ...uint32) map[uint32]bool {
	m := make(map[uint32]bool, len(tids))
	for _, t := range tids {
		m[t] = true
	}
	return m
}

// The thread #150 described: asleep since before the window opened. The
// tracer closes the open interval at read time, so each window carries its
// own second of sleep instead of 0 and then one capped burst.
func TestKnownThreadAsleepAcrossWindowsReadsFullEveryWindow(t *testing.T) {
	w := newThreadWindows()
	base := 100 * sec
	// Sample 1: the baseline. The thread fell asleep at base-0.5s, so the
	// open interval already holds half a second.
	if sh := w.known(7, bpf.ThreadTotals{OnNs: 3 * sec, OffNs: sec / 2, At: base}); sh != (threadShare{}) {
		t.Fatalf("the first sample has no window, got %+v", sh)
	}
	w.end(base, alive(7))
	for i := uint64(1); i <= 3; i++ {
		at := base + i*sec
		sh := w.known(7, bpf.ThreadTotals{OnNs: 3 * sec, OffNs: sec/2 + i*sec, At: at})
		if !near(sh.off, 100) || sh.on != 0 || sh.runq != 0 {
			t.Fatalf("window %d: want 100%% off-CPU, got %+v", i, sh)
		}
		w.end(at, alive(7))
	}
}

func TestPreemptedTimeIsRunQueueNotOffCPU(t *testing.T) {
	w := newThreadWindows()
	w.known(9, bpf.ThreadTotals{At: 10 * sec})
	w.end(10*sec, alive(9))
	sh := w.known(9, bpf.ThreadTotals{OnNs: 6 * sec / 10, RunqNs: 4 * sec / 10, CtxSwitches: 200, At: 11 * sec})
	if !near(sh.on, 60) || !near(sh.runq, 40) || sh.off != 0 || sh.switches != 200 {
		t.Fatalf("want 60%% on, 40%% run queue, 0 off, 200 switches; got %+v", sh)
	}
	if !near(sh.on+sh.off+sh.runq, 100) {
		t.Fatalf("a thread known for the whole window adds to 100%%, got %v", sh.on+sh.off+sh.runq)
	}
}

// Each thread's window runs between ITS readings, so a reading late by a few
// microseconds is still divided by its own span.
func TestTheWindowIsTheThreadsOwnReadings(t *testing.T) {
	w := newThreadWindows()
	w.known(1, bpf.ThreadTotals{At: 10 * sec})
	w.end(10*sec, alive(1))
	sh := w.known(1, bpf.ThreadTotals{OnNs: 2 * sec, At: 12 * sec})
	if !near(sh.on, 100) {
		t.Fatalf("2s on in a 2s window is 100%%, got %v", sh.on)
	}
}

// A torn read can show a total ahead of where the next read puts it. The
// high-water mark keeps the next window from going negative or counting the
// overlap twice.
func TestATotalThatGoesBackwardsDoesNotWrapOrCountTwice(t *testing.T) {
	w := newThreadWindows()
	w.known(3, bpf.ThreadTotals{At: 10 * sec})
	w.end(10*sec, alive(3))
	w.known(3, bpf.ThreadTotals{OnNs: 1200 * sec / 1000, At: 11 * sec}) // over by 0.2s
	w.end(11*sec, alive(3))
	sh := w.known(3, bpf.ThreadTotals{OnNs: 1100 * sec / 1000, At: 12 * sec})
	if sh.on != 0 {
		t.Fatalf("a total below the mark adds nothing, got %v", sh.on)
	}
	w.end(12*sec, alive(3))
	sh = w.known(3, bpf.ThreadTotals{OnNs: 2 * sec, At: 13 * sec})
	if !near(sh.on, 80) {
		t.Fatalf("the window after counts from the mark (1.2s), want 80%%, got %v", sh.on)
	}
}

// No entry in the tracer means no switch-out since the attach. Asleep now,
// then, means asleep the whole time: going back to sleep after running would
// have been a switch-out.
func TestUnseenThreadAsleepReadsFullOffCPU(t *testing.T) {
	w := newThreadWindows()
	if sh := w.unseen(4, 'S', 0, 50*sec, 100); sh != (threadShare{}) {
		t.Fatalf("no window before the first sample, got %+v", sh)
	}
	w.end(50*sec, alive(4))
	for _, st := range []byte{'S', 'D', 'T'} {
		if sh := w.unseen(4, st, 0, 51*sec, 100); sh.off != 100 || sh.on != 0 || sh.runq != 0 {
			t.Fatalf("state %c: want 100%% off-CPU, got %+v", st, sh)
		}
	}
}

func TestUnseenRunningThreadReadsOnCPUFromProcTicks(t *testing.T) {
	w := newThreadWindows()
	w.unseen(5, 'R', 1000, 50*sec, 100)
	w.end(50*sec, alive(5))
	sh := w.unseen(5, 'R', 1095, 51*sec, 100) // 95 ticks at 100Hz in 1s
	if !near(sh.on, 95) || sh.off != 0 {
		t.Fatalf("want 95%% on from the tick counters, got %+v", sh)
	}
}

func TestUnseenExitedThreadReadsNothing(t *testing.T) {
	w := newThreadWindows()
	w.end(50*sec, alive(6))
	for _, st := range []byte{'Z', 'X'} {
		if sh := w.unseen(6, st, 0, 51*sec, 100); sh != (threadShare{}) {
			t.Fatalf("state %c: want nothing, got %+v", st, sh)
		}
	}
}

// A thread asleep since before the attach wakes, runs and is switched out:
// its first entry appears with totals from that switch-out on. Its window
// starts at the last sample and its baseline is zero, so it reads what the
// tracer saw and nothing negative — the slice before the first switch-out is
// the warm-up.
func TestAThreadFirstKnownMidWindowCountsFromTheLastSample(t *testing.T) {
	w := newThreadWindows()
	w.unseen(8, 'S', 0, 50*sec, 100)
	w.end(50*sec, alive(8))
	sh := w.known(8, bpf.ThreadTotals{OffNs: sec / 4, CtxSwitches: 1, At: 51 * sec})
	if !near(sh.off, 25) || sh.on != 0 || sh.switches != 1 {
		t.Fatalf("want the 0.25s the tracer saw, got %+v", sh)
	}
}

func TestEndForgetsThreadsThatExited(t *testing.T) {
	w := newThreadWindows()
	w.known(1, bpf.ThreadTotals{At: sec})
	w.unseen(2, 'R', 10, sec, 100)
	w.end(sec, alive(1))
	if _, ok := w.prev[1]; !ok {
		t.Fatal("a live thread's mark was dropped")
	}
	if _, ok := w.ticks[2]; ok {
		t.Fatal("an exited thread's ticks were kept")
	}
}
