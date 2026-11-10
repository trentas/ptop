//go:build linux && ebpf

package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/trentas/ptop/internal/bpf"
	"github.com/trentas/ptop/pkg/collector"
)

// ─── threads: the interval still open, and the run queue (#150) ────────────
//
// Four planted threads, each with a known answer in every window:
//
//   - one asleep since before the tracer attached, for the whole case. The
//     tracer never sees it switched out, so the collector has only /proc's
//     state to go on;
//   - one asleep from mid-case on, after running. The tracer knows it, and its
//     sleep is an interval still open at every read;
//   - two burners pinned to one CPU. Each is preempted for the other, so about
//     half its time is a wait for a CPU, not a sleep;
//   - on the same CPU, a SCHED_IDLE thread that sleeps 1ms at a time. A
//     SCHED_IDLE task does not preempt the burners when it wakes, so nearly
//     all its time is the wait for a CPU after each wakeup.
//
// Before #150 both sleepers read 0% off-CPU in every window, and the burners'
// wait for the CPU read as off-CPU. Before #151's sched_wakeup the idle
// sleeper's wait after each wakeup read as asleep.

// threadsWindow is one published snapshot and the span it covers, from the
// previous snapshot's arrival to its own.
type threadsWindow struct {
	from, to time.Time
	byTID    map[int]collector.ThreadInfo
}

// runqAt is a RunqLatency snapshot and when it arrived.
type runqAt struct {
	at time.Time
	h  collector.RunqLatency
}

// idleSleeper sleeps 1ms at a time until until, as SCHED_IDLE, then puts the
// thread back to SCHED_OTHER before it returns to the runtime.
func idleSleeper(tid chan<- int, until time.Time) error {
	if err := unix.SchedSetAttr(0, &unix.SchedAttr{Policy: unix.SCHED_IDLE}, 0); err != nil {
		tid <- 0
		return fmt.Errorf("SCHED_IDLE: %w", err)
	}
	defer func() { _ = unix.SchedSetAttr(0, &unix.SchedAttr{Policy: unix.SCHED_NORMAL}, 0) }()
	tid <- unix.Gettid()
	nap := unix.NsecToTimespec(int64(time.Millisecond))
	for time.Now().Before(until) {
		_ = unix.ClockNanosleep(unix.CLOCK_MONOTONIC, 0, &nap, nil)
	}
	return nil
}

var threadsBurnSink uint64

//go:noinline
func plantedPreempted(until time.Time) uint64 {
	var acc uint64
	for time.Now().Before(until) {
		for i := 0; i < 20_000; i++ {
			acc = acc*1664525 + 1013904223
		}
	}
	return acc
}

// sleepUntil sleeps to an absolute CLOCK_MONOTONIC deadline, so a sleep cut
// short and re-issued still ends when it was meant to.
func sleepUntil(deadline uint64) {
	ts := unix.NsecToTimespec(int64(deadline))
	for unix.ClockNanosleep(unix.CLOCK_MONOTONIC, unix.TIMER_ABSTIME, &ts, nil) == unix.EINTR {
	}
}

// threadState reads a thread's one-letter state from /proc.
func threadState(tid int) byte {
	b, err := os.ReadFile(fmt.Sprintf("/proc/self/task/%d/stat", tid))
	if err != nil {
		return 0
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		return 0
	}
	return s[i+2]
}

func checkThreads(g *grader, pid int) {
	cpus, err := allowedCPUs()
	if err != nil || len(cpus) == 0 {
		g.broken("threads", "the CPUs this process may run on", fmt.Errorf("%v (%d CPUs)", err, len(cpus)))
		return
	}
	shared := cpus[len(cpus)-1]
	// Every planted thread is a locked OS thread, and a locked thread whose
	// goroutine waits for a Go P sleeps in the kernel until it gets one. With
	// the burners and the idle sleeper holding every P, they would park each
	// other and read asleep for the Go scheduler's reasons, not the kernel's.
	// A P for each of them, and for the collector, keeps the measurement the
	// kernel's.
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(len(cpus) + 4))
	t0, err := bpf.MonotonicNanos()
	if err != nil {
		g.broken("threads", "the monotonic clock", err)
		return
	}
	// Both sleepers wake after the collector has stopped.
	wake := t0 + uint64(7500*time.Millisecond)

	var wg sync.WaitGroup
	defer wg.Wait()
	sleeper := func() int {
		tid := make(chan int, 1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			quietThread(func() {
				tid <- unix.Gettid()
				sleepUntil(wake)
			})
		}()
		return <-tid
	}

	early := sleeper()
	for deadline := time.Now().Add(time.Second); threadState(early) != 'S' && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	if st := threadState(early); st != 'S' {
		g.broken("threads", "the early sleeper asleep before the attach", fmt.Errorf("its state is %q", st))
		return
	}

	c := collector.NewThreadsEBPFCollector()
	if err := c.Start(pid); err != nil {
		g.broken("threads", "attach", err)
		return
	}
	attach := time.Now()
	var windows []threadsWindow
	var runq []runqAt
	stop, received := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(received)
		last := attach
		ch := c.Subscribe()
		for {
			select {
			case v := <-ch:
				if h, ok := v.(collector.RunqLatency); ok {
					runq = append(runq, runqAt{at: time.Now(), h: h})
					continue
				}
				ts, ok := v.([]collector.ThreadInfo)
				if !ok {
					continue
				}
				now := time.Now()
				w := threadsWindow{from: last, to: now, byTID: make(map[int]collector.ThreadInfo, len(ts))}
				for _, t := range ts {
					w.byTID[t.TID] = t
				}
				windows = append(windows, w)
				last = now
			case <-stop:
				return
			}
		}
	}()

	time.Sleep(time.Until(attach.Add(1500 * time.Millisecond)))
	late := sleeper()
	lateAsleep := time.Now()

	burnUntil := attach.Add(5500 * time.Millisecond)
	burnTIDs := make(chan int, 2)
	pinErrs := make([]error, 2)
	for i := range pinErrs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pinErrs[i] = onCPU(shared, func() {
				burnTIDs <- unix.Gettid()
				threadsBurnSink += plantedPreempted(burnUntil)
			})
		}()
	}
	burners := []int{<-burnTIDs, <-burnTIDs}
	idleTID := make(chan int, 1)
	var idleErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		pinErr := onCPU(shared, func() { idleErr = idleSleeper(idleTID, burnUntil) })
		if idleErr == nil {
			idleErr = pinErr
		}
	}()
	idle := <-idleTID
	burnStart := time.Now()

	time.Sleep(time.Until(attach.Add(6200 * time.Millisecond)))
	close(stop)
	<-received
	c.Stop()
	for _, err := range pinErrs {
		if err != nil {
			g.broken("threads", fmt.Sprintf("pin the burners to CPU %d", shared), err)
			return
		}
	}

	// A window is graded only if the planted state held from its start to its
	// end, with a margin for the gap between the collector's read and the
	// snapshot's arrival. The first snapshot is the collector's baseline.
	const margin = 50 * time.Millisecond
	span := func(tid int, from, to time.Time) []collector.ThreadInfo {
		var out []collector.ThreadInfo
		for i, w := range windows {
			if i == 0 || w.from.Before(from.Add(margin)) || w.to.After(to.Add(-margin)) {
				continue
			}
			if t, ok := w.byTID[tid]; ok {
				out = append(out, t)
			}
		}
		return out
	}
	end := attach.Add(6200 * time.Millisecond)
	g.note("threads", "%d snapshots; burners on CPU %d", len(windows), shared)

	sleeperCheck := func(who string, tid int, from time.Time) {
		ws := span(tid, from, end)
		if len(ws) < 2 {
			g.broken("threads", who, fmt.Errorf("%d windows with the thread asleep throughout, want at least 2", len(ws)))
			return
		}
		g.check("threads", who+": off-CPU in every window", allWindows(ws, func(t collector.ThreadInfo) bool {
			return t.OffCpuPct >= 99 && t.CPUPct+t.RunqWaitPct <= 1
		}), "≥ 99% off, ≤ 1% on + run queue", shares(ws))
	}
	sleeperCheck("asleep since before the attach", early, attach)
	sleeperCheck("asleep since mid-case, after running (#150)", late, lateAsleep)

	// The wait after a wakeup is run-queue time (#151).
	if idleErr != nil || idle == 0 {
		g.broken("threads", "the SCHED_IDLE sleeper", fmt.Errorf("%v", idleErr))
	} else if ws := span(idle, burnStart, burnUntil); len(ws) < 2 {
		g.broken("threads", "SCHED_IDLE sleeper", fmt.Errorf("%d windows inside the burn, want at least 2", len(ws)))
	} else {
		g.check("threads", "SCHED_IDLE sleeper beside the burners: its wait after each wakeup is run queue, not asleep (#151)",
			// Measured: ~0/40/60 with sched_wakeup, 0/100/0 without it.
			allWindows(ws, func(t collector.ThreadInfo) bool { return t.RunqWaitPct >= 25 && t.OffCpuPct <= 75 }),
			"run queue ≥ 25%, off ≤ 75% (0/100/0 without sched_wakeup)", shares(ws))
	}

	var burnerRunq time.Duration
	for i, tid := range burners {
		who := fmt.Sprintf("burner %d of 2 on one CPU", i+1)
		ws := span(tid, burnStart, burnUntil)
		if len(ws) < 2 {
			g.broken("threads", who, fmt.Errorf("%d windows inside the burn, want at least 2", len(ws)))
			continue
		}
		for _, t := range ws {
			burnerRunq += time.Duration(t.RunqWaitPct / 100 * float64(time.Second))
		}
		g.check("threads", who+": the wait for the CPU is run queue, not off-CPU (#150)",
			allWindows(ws, func(t collector.ThreadInfo) bool {
				return t.RunqWaitPct >= 25 && t.RunqWaitPct <= 75 && t.CPUPct >= 25 && t.CPUPct <= 75 && t.OffCpuPct <= 10
			}), "on and run queue each in [25%, 75%], off ≤ 10%", shares(ws))
		g.check("threads", who+": on + off + run queue cover the window",
			allWindows(ws, func(t collector.ThreadInfo) bool {
				s := t.CPUPct + t.OffCpuPct + t.RunqWaitPct
				return s >= 97 && s <= 100.5
			}), "[97%, 100%]", sums(ws))
	}

	// The run-queue histogram holds the same waits by length: over the burn it
	// has at least the burners' (#151). Snapshots are cumulative.
	var before, after *collector.RunqLatency
	for i := range runq {
		if !runq[i].at.After(burnStart.Add(margin)) {
			before = &runq[i].h
		}
		if !runq[i].at.After(burnUntil.Add(-margin)) {
			after = &runq[i].h
		}
	}
	if before == nil || after == nil || after.Count <= before.Count {
		g.broken("threads", "run-queue histogram over the burn", fmt.Errorf("%d snapshots, none bracketing the burn", len(runq)))
		return
	}
	sum := time.Duration(after.SumNs - before.SumNs)
	g.note("threads", "run-queue histogram over the burn: %d waits, %v", after.Count-before.Count, sum.Round(time.Millisecond))
	g.check("threads", "the run-queue histogram holds at least the burners' waits", sum >= burnerRunq*8/10,
		fmt.Sprintf("≥ 80%% of %v", burnerRunq.Round(time.Millisecond)), sum.Round(time.Millisecond).String())
}

func allWindows(ws []collector.ThreadInfo, ok func(collector.ThreadInfo) bool) bool {
	for _, t := range ws {
		if !ok(t) {
			return false
		}
	}
	return len(ws) > 0
}

// shares renders each window as on/off/run-queue percentages.
func shares(ws []collector.ThreadInfo) string {
	parts := make([]string, len(ws))
	for i, t := range ws {
		parts[i] = fmt.Sprintf("%.0f/%.0f/%.0f", t.CPUPct, t.OffCpuPct, t.RunqWaitPct)
	}
	return "on/off/runq " + strings.Join(parts, " ")
}

func sums(ws []collector.ThreadInfo) string {
	parts := make([]string, len(ws))
	for i, t := range ws {
		parts[i] = fmt.Sprintf("%.1f", t.CPUPct+t.OffCpuPct+t.RunqWaitPct)
	}
	return strings.Join(parts, " ")
}
