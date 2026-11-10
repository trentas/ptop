package bpf

// ThreadState mirrors `struct thread_state` in programs/threads.bpf.c 1:1:
// 7 × u64, in the same order (the order is part of how a read avoids counting
// an interval twice; see the struct's comment there).
type ThreadState struct {
	OnCpuNsTotal  uint64
	OffCpuNsTotal uint64 // asleep (S, D, T...)
	RunqNsTotal   uint64 // runnable, waiting for a CPU after a preemption
	CtxSwitches   uint64
	LastOnCpuNs   uint64
	LastOffCpuNs  uint64
	OffKind       uint64 // offAsleep, offRunnable or offExited
}

// The kinds of off interval, as threads.bpf.c writes them in off_kind.
const (
	offAsleep   = 0
	offRunnable = 1
	offExited   = 2
)

// ThreadTotals is one thread's time since the tracer attached, split three
// ways, with the interval open at At included. CtxSwitches counts switch-outs.
type ThreadTotals struct {
	OnNs        uint64
	OffNs       uint64 // asleep
	RunqNs      uint64 // runnable, not on a CPU
	CtxSwitches uint64
	At          uint64 // CLOCK_MONOTONIC when the entry was read
}

// closeAt adds the interval that is still open to the total it will close
// into, up to at (#150). The later of the two stamps is the open interval: the
// program stamps last_on_cpu_ns at a switch-in and last_off_cpu_ns at a
// switch-out. Neither stamp set is a thread whose state we have not seen yet.
func (s ThreadState) closeAt(at uint64) ThreadTotals {
	tt := ThreadTotals{
		OnNs:        s.OnCpuNsTotal,
		OffNs:       s.OffCpuNsTotal,
		RunqNs:      s.RunqNsTotal,
		CtxSwitches: s.CtxSwitches,
		At:          at,
	}
	switch {
	case s.LastOnCpuNs > s.LastOffCpuNs:
		if at > s.LastOnCpuNs {
			tt.OnNs += at - s.LastOnCpuNs
		}
	case s.LastOffCpuNs != 0 && at > s.LastOffCpuNs:
		open := at - s.LastOffCpuNs
		switch s.OffKind {
		case offAsleep:
			tt.OffNs += open
		case offRunnable:
			tt.RunqNs += open
		}
	}
	return tt
}

// RunqBuckets is the run-queue histogram's bucket count: bucket i holds the
// waits of [2^i, 2^(i+1)) µs, bucket 0 those under 2 µs, the last everything
// longer.
const RunqBuckets = 32

// RunqHist mirrors `struct runq_hist` in programs/threads.bpf.c: the target's
// waits for a CPU by length, cumulative since the attach (#151).
type RunqHist struct {
	Bucket [RunqBuckets]uint64
	Count  uint64
	SumNs  uint64
}
