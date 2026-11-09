//go:build linux

package collector

import "github.com/trentas/ptop/internal/bpf"

// threadWindows turns the threads tracer's since-attach totals into the share
// of each window a thread spent on a CPU, asleep and waiting for a CPU (#150).
//
// Each thread's window runs from the moment its entry was last read to the
// moment it is read now, both on the clock the program stamps with, so the
// three shares of a thread the tracer knows for the whole window add up to
// 100% of it.
type threadWindows struct {
	prev   map[uint32]threadMark
	ticks  map[uint32]uint64 // /proc utime+stime, for threads the tracer has not seen
	lastAt uint64            // CLOCK_MONOTONIC at the end of the last sample; 0 before the first
}

// threadMark is what a thread's totals were at its last reading, kept as a
// high-water mark: a torn read of the map (see thread_state in threads.bpf.c)
// can only move time into the next window, never make a total go backwards.
type threadMark struct {
	on, off, runq, sw uint64
	at                uint64
}

type threadShare struct {
	on, off, runq float64 // percent of the window
	switches      uint64
}

func newThreadWindows() *threadWindows {
	return &threadWindows{prev: make(map[uint32]threadMark), ticks: make(map[uint32]uint64)}
}

// known reads a thread the tracer has an entry for.
func (w *threadWindows) known(tid uint32, tt bpf.ThreadTotals) threadShare {
	p, seen := w.prev[tid]
	start := p.at
	if !seen {
		// First known in this window: it had no entry at the last sample, so
		// everything in its totals happened after it.
		start = w.lastAt
	}
	var sh threadShare
	if start != 0 && tt.At > start {
		el := float64(tt.At - start)
		sh.on = windowPct(grown(tt.OnNs, p.on), el)
		sh.off = windowPct(grown(tt.OffNs, p.off), el)
		sh.runq = windowPct(grown(tt.RunqNs, p.runq), el)
		sh.switches = grown(tt.CtxSwitches, p.sw)
	}
	w.prev[tid] = threadMark{
		on:   max(p.on, tt.OnNs),
		off:  max(p.off, tt.OffNs),
		runq: max(p.runq, tt.RunqNs),
		sw:   max(p.sw, tt.CtxSwitches),
		at:   max(p.at, tt.At),
	}
	delete(w.ticks, tid)
	return sh
}

// unseen reads a thread the tracer has no entry for: it has not been switched
// out since the attach. Its /proc state then says where it has been the whole
// time:
//
//   - Not running now (S, D, T...): it cannot have run since the attach, since
//     going back to sleep would have been a switch-out. It was asleep for the
//     whole window — the thread #150 saw read 0% off-CPU forever.
//   - Running (R): it has been on a CPU since before the attach, or since soon
//     after it, never preempted. On-CPU comes from /proc's tick counters, the
//     only reading there is for it.
//   - Exited (Z, X): nothing.
//
// The premise fails only when tid_state is full (8192 threads), where a thread
// can be switched out and still have no entry.
func (w *threadWindows) unseen(tid uint32, state byte, ticks, at uint64, clkTck float64) threadShare {
	prevTicks, hadTicks := w.ticks[tid]
	w.ticks[tid] = ticks
	var sh threadShare
	if w.lastAt == 0 || at <= w.lastAt {
		return sh
	}
	el := float64(at - w.lastAt)
	switch state {
	case 'Z', 'X':
	case 'R':
		if hadTicks && ticks >= prevTicks && clkTck > 0 {
			sh.on = windowPct(uint64(float64(ticks-prevTicks)/clkTck*1e9), el)
		}
	default:
		sh.off = 100
	}
	return sh
}

// end closes a sample: at is the clock after the map was read, and alive the
// TIDs /proc listed, so threads that exited stop being remembered.
func (w *threadWindows) end(at uint64, alive map[uint32]bool) {
	w.lastAt = at
	for tid := range w.prev {
		if !alive[tid] {
			delete(w.prev, tid)
		}
	}
	for tid := range w.ticks {
		if !alive[tid] {
			delete(w.ticks, tid)
		}
	}
}

func grown(now, before uint64) uint64 {
	if now <= before {
		return 0
	}
	return now - before
}

// windowPct is ns as a percentage of a window el ns long, capped at 100: a
// torn read can put a little more than a window in one.
func windowPct(ns uint64, el float64) float64 {
	p := float64(ns) / el * 100
	if p > 100 {
		return 100
	}
	return p
}
