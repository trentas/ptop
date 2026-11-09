//go:build linux && ebpf

package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trentas/ptop/internal/bpf"
)

// ThreadsEBPFCollector is a hybrid /proc + eBPF collector:
//
//   - /proc/<pid>/task/<tid>/{stat,wchan} → textual state, comm, wchan
//     (info that only /proc has in canonical form)
//   - eBPF tid_state via tracepoint sched:sched_switch → each thread's time
//     on a CPU, asleep and waiting for a CPU, plus its context switches
//
// Result: ThreadInfo with everything /proc gave + window ctx_switches + the
// share of the window each thread spent on-CPU, off-CPU and in the run queue,
// counting the interval still open when the window closes (#150).
//
// Lifecycle:
//   - tick every 1s
//   - read /proc/<pid>/task/ → collect state/wchan/name + list of live TIDs
//   - prune tid_state for TIDs that have exited
//   - read the tracer's totals, the open interval included, and turn them
//     into shares of each thread's window (threadWindows)
//   - publish []ThreadInfo
type ThreadsEBPFCollector struct {
	tracer *bpf.ThreadsTracer
	pid    int
	ch     chan interface{}
	stop   chan struct{}

	mu      sync.Mutex
	windows *threadWindows
}

func NewThreadsEBPFCollector() *ThreadsEBPFCollector {
	return &ThreadsEBPFCollector{
		ch:      make(chan interface{}, 4),
		stop:    make(chan struct{}),
		windows: newThreadWindows(),
	}
}

func (c *ThreadsEBPFCollector) Start(pid int) error {
	if _, err := os.Stat(fmt.Sprintf("/proc/%d/task", pid)); err != nil {
		return fmt.Errorf("process %d not found: %w", pid, err)
	}
	tracer, err := bpf.OpenThreadsTracer(bpf.TargetPID(pid))
	if err != nil {
		return fmt.Errorf("threads eBPF: %w", err)
	}
	c.tracer = tracer
	c.pid = pid
	go c.loop()
	return nil
}

func (c *ThreadsEBPFCollector) Stop() {
	close(c.stop)
	if c.tracer != nil {
		_ = c.tracer.Close()
		c.tracer = nil
	}
}

func (c *ThreadsEBPFCollector) Subscribe() <-chan interface{} {
	return c.ch
}

func (c *ThreadsEBPFCollector) loop() {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			if threads, err := c.collect(); err == nil {
				publish(c.ch, threads)
			}
		}
	}
}

func (c *ThreadsEBPFCollector) collect() ([]ThreadInfo, error) {
	taskDir := fmt.Sprintf("/proc/%d/task", c.pid)
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// 1st pass: read /proc/task/* and build TID list + metadata.
	type procData struct {
		comm  string
		state byte
		ticks uint64
		wchan string
	}
	procByTID := make(map[uint32]procData, len(entries))
	alive := make(map[uint32]bool, len(entries))
	tidList := make([]int, 0, len(entries))
	for _, e := range entries {
		tid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		statData, err := os.ReadFile(filepath.Join(taskDir, e.Name(), "stat"))
		if err != nil {
			continue
		}
		comm, state, ticks, ok := parseThreadStat(statData)
		if !ok {
			continue
		}
		wchan := ""
		if w, err := os.ReadFile(filepath.Join(taskDir, e.Name(), "wchan")); err == nil {
			wchan = strings.TrimSpace(string(w))
			if wchan == "0" {
				wchan = ""
			}
		}
		procByTID[uint32(tid)] = procData{comm: comm, state: state, ticks: ticks, wchan: wchan}
		alive[uint32(tid)] = true
		tidList = append(tidList, tid)
	}

	// Prune tid_state for threads that exited since the last tick.
	if err := c.tracer.PruneDeadTIDs(tidList); err != nil {
		// Not fatal: keep publishing /proc data even if the prune fails.
		_ = err
	}

	// 2nd pass: the tracer's totals, then the clock that closes the window
	// for the threads it has no entry for.
	totals, err := c.tracer.Totals()
	if err != nil {
		// Without the totals every thread would read as unseen, and a running
		// one as asleep. Publish /proc's view with no shares instead.
		totals = nil
	}
	endAt, clockErr := bpf.MonotonicNanos()

	out := make([]ThreadInfo, 0, len(procByTID))
	for tid, pd := range procByTID {
		var sh threadShare
		if tt, ok := totals[tid]; ok {
			sh = c.windows.known(tid, tt)
		} else if err == nil && clockErr == nil {
			sh = c.windows.unseen(tid, pd.state, pd.ticks, endAt, clkTck)
		}
		out = append(out, ThreadInfo{
			TID:         int(tid),
			Name:        pd.comm,
			State:       mapThreadState(pd.state),
			CPUPct:      sh.on,
			Waiting:     pd.wchan,
			CtxSwitches: sh.switches,
			OffCpuPct:   sh.off,
			RunqWaitPct: sh.runq,
		})
	}
	if clockErr == nil {
		c.windows.end(endAt, alive)
	}
	return out, nil
}
