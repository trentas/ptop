package bpf

import (
	"testing"
	"unsafe"
)

func TestThreadStateMatchesTheProgramsLayout(t *testing.T) {
	// threads.bpf.c: struct thread_state is 7 × __u64.
	if got := unsafe.Sizeof(ThreadState{}); got != 56 {
		t.Fatalf("ThreadState is %d bytes, the program's struct is 56", got)
	}
}

func TestCloseAtAddsTheOpenInterval(t *testing.T) {
	const at = 10_000
	cases := []struct {
		name string
		s    ThreadState
		want ThreadTotals
	}{
		{
			name: "on a CPU since 4000: the running slice counts",
			s:    ThreadState{OnCpuNsTotal: 100, OffCpuNsTotal: 50, LastOnCpuNs: 4000, LastOffCpuNs: 3000},
			want: ThreadTotals{OnNs: 100 + 6000, OffNs: 50, At: at},
		},
		{
			name: "asleep since 2000: the sleep so far is off-CPU (#150)",
			s:    ThreadState{OnCpuNsTotal: 100, LastOnCpuNs: 1000, LastOffCpuNs: 2000, OffKind: offAsleep},
			want: ThreadTotals{OnNs: 100, OffNs: 8000, At: at},
		},
		{
			name: "preempted at 2000: the wait is run-queue, not off-CPU (#150)",
			s:    ThreadState{OffCpuNsTotal: 7, LastOnCpuNs: 1000, LastOffCpuNs: 2000, OffKind: offRunnable},
			want: ThreadTotals{OffNs: 7, RunqNs: 8000, At: at},
		},
		{
			name: "exited: nothing stays open",
			s:    ThreadState{OnCpuNsTotal: 100, LastOnCpuNs: 1000, LastOffCpuNs: 2000, OffKind: offExited},
			want: ThreadTotals{OnNs: 100, At: at},
		},
		{
			name: "first seen at a switch-in it did not finish: nothing open is known",
			s:    ThreadState{},
			want: ThreadTotals{At: at},
		},
		{
			name: "a stamp after the read clock adds nothing rather than wrapping",
			s:    ThreadState{OnCpuNsTotal: 5, LastOnCpuNs: at + 10, LastOffCpuNs: 1},
			want: ThreadTotals{OnNs: 5, At: at},
		},
	}
	for _, c := range cases {
		if got := c.s.closeAt(at); got != c.want {
			t.Errorf("%s:\n got %+v\nwant %+v", c.name, got, c.want)
		}
	}
}
