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
//   - eBPF tid_state via tracepoint sched:sched_switch → CPU% based on
//     real on-CPU time + per-TID context switch count in the window
//
// Result: ThreadInfo with everything /proc gave + window ctx_switches +
// more accurate CPU% (window-based instead of cumulative).
//
// Lifecycle:
//   - tick every 1s
//   - read /proc/<pid>/task/ → collect state/wchan/name + list of live TIDs
//   - prune tid_state for TIDs that have exited
//   - read tid_state from BPF, compute deltas vs previous snapshot
//   - publish []ThreadInfo
type ThreadsEBPFCollector struct {
	tracer *bpf.ThreadsTracer
	pid    int
	ch     chan interface{}
	stop   chan struct{}

	mu           sync.Mutex
	prevOnNs     map[uint32]uint64 // tid → on_cpu_ns_total at last sample
	prevOffNs    map[uint32]uint64 // tid → off_cpu_ns_total at last sample
	prevSwitch   map[uint32]uint64 // tid → ctx_switches at last sample
	lastSampleAt time.Time
}

func NewThreadsEBPFCollector() *ThreadsEBPFCollector {
	return &ThreadsEBPFCollector{
		ch:         make(chan interface{}, 4),
		stop:       make(chan struct{}),
		prevOnNs:   make(map[uint32]uint64),
		prevOffNs:  make(map[uint32]uint64),
		prevSwitch: make(map[uint32]uint64),
	}
}

func (c *ThreadsEBPFCollector) Start(pid int) error {
	if _, err := os.Stat(fmt.Sprintf("/proc/%d/task", pid)); err != nil {
		return fmt.Errorf("process %d not found: %w", pid, err)
	}
	tracer, err := bpf.OpenThreadsTracer(pid)
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
				select {
				case c.ch <- threads:
				default:
				}
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

	now := time.Now()
	elapsed := 0.0
	if !c.lastSampleAt.IsZero() {
		elapsed = now.Sub(c.lastSampleAt).Seconds()
	}

	// 1st pass: read /proc/task/* and build TID list + metadata.
	type procData struct {
		comm  string
		state byte
		wchan string
	}
	procByTID := make(map[uint32]procData, len(entries))
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
		comm, state, _, ok := parseThreadStat(statData)
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
		procByTID[uint32(tid)] = procData{comm: comm, state: state, wchan: wchan}
		tidList = append(tidList, tid)
	}

	// Prune tid_state for threads that exited since the last tick.
	if err := c.tracer.PruneDeadTIDs(tidList); err != nil {
		// Not fatal: keep publishing /proc data even if the prune fails.
		_ = err
	}

	// 2nd pass: read tid_state and compute deltas.
	stats, err := c.tracer.Stats()
	if err != nil {
		stats = nil
	}

	out := make([]ThreadInfo, 0, len(procByTID))
	for tid, pd := range procByTID {
		s := stats[tid]
		var cpuPct, offCpuPct float64
		var switches uint64

		if elapsed > 0 {
			deltaOn := s.OnCpuNsTotal - c.prevOnNs[tid]
			cpuPct = (float64(deltaOn) / 1e9) / elapsed * 100
			if cpuPct > 100 {
				cpuPct = 100 // ceiling — single thread on multi-core can't exceed 100%
			}
			deltaOff := s.OffCpuNsTotal - c.prevOffNs[tid]
			offCpuPct = (float64(deltaOff) / 1e9) / elapsed * 100
			if offCpuPct > 100 {
				offCpuPct = 100 // same single-thread ceiling
			}
			switches = s.CtxSwitches - c.prevSwitch[tid]
		}
		c.prevOnNs[tid] = s.OnCpuNsTotal
		c.prevOffNs[tid] = s.OffCpuNsTotal
		c.prevSwitch[tid] = s.CtxSwitches

		out = append(out, ThreadInfo{
			TID:         int(tid),
			Name:        pd.comm,
			State:       mapThreadState(pd.state),
			CPUPct:      cpuPct,
			Waiting:     pd.wchan,
			CtxSwitches: switches,
			OffCpuPct:   offCpuPct,
		})
	}

	// Garbage collect prev maps for TIDs that disappeared.
	for tid := range c.prevOnNs {
		if _, alive := procByTID[tid]; !alive {
			delete(c.prevOnNs, tid)
			delete(c.prevOffNs, tid)
			delete(c.prevSwitch, tid)
		}
	}

	c.lastSampleAt = now
	return out, nil
}
