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

	// The threads program keys a thread by its tid in the TARGET's pid
	// namespace, while /proc/<pid>/task lists tids in the namespace ptop reads
	// /proc from. The two differ when the target lives below it — a container
	// seen from the host, or from a `pid: host` container (#197). nested says
	// so, decided once at Start; kernelTIDs caches each live thread's inner tid,
	// read from its NSpid, so a thread costs one status read, not one a tick.
	nested     bool
	kernelTIDs map[uint32]uint32
}

func NewThreadsEBPFCollector() *ThreadsEBPFCollector {
	return &ThreadsEBPFCollector{
		ch:         make(chan interface{}, 4),
		stop:       make(chan struct{}),
		windows:    newThreadWindows(),
		kernelTIDs: map[uint32]uint32{},
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
	// The target filter already refused a target whose NSpid it could not
	// read, so this chain is there; more than one entry is a nested target.
	c.nested = len(bpf.NSpidChain(fmt.Sprintf("/proc/%d/status", pid))) > 1
	go c.loop()
	return nil
}

// kernelTID is the key the threads program files tid under (see kernelTIDs).
// ok is false when a nested target's thread cannot be translated — it exited
// between the listing and the read — and then its totals are not looked up,
// rather than looked up under some other thread's number.
func (c *ThreadsEBPFCollector) kernelTID(taskDir, name string, tid uint32) (uint32, bool) {
	if !c.nested {
		return tid, true
	}
	if k, ok := c.kernelTIDs[tid]; ok {
		return k, true
	}
	chain := bpf.NSpidChain(filepath.Join(taskDir, name, "status"))
	if len(chain) == 0 || chain[0] != int(tid) {
		return 0, false
	}
	k := uint32(chain[len(chain)-1])
	c.kernelTIDs[tid] = k
	return k, true
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
			if h, err := c.runqLatency(); err == nil {
				publish(c.ch, h)
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
		// key is the thread's tid as the threads program files it; keyed is
		// false when it could not be translated (see kernelTID).
		key   uint32
		keyed bool
	}
	procByTID := make(map[uint32]procData, len(entries))
	alive := make(map[uint32]bool, len(entries))
	liveKeys := make([]int, 0, len(entries))
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
		key, keyed := c.kernelTID(taskDir, e.Name(), uint32(tid))
		procByTID[uint32(tid)] = procData{comm: comm, state: state, ticks: ticks, wchan: wchan, key: key, keyed: keyed}
		alive[uint32(tid)] = true
		if keyed {
			liveKeys = append(liveKeys, int(key))
		}
	}
	for tid := range c.kernelTIDs {
		if !alive[tid] {
			delete(c.kernelTIDs, tid)
		}
	}

	// Prune tid_state for threads that exited since the last tick. The map is
	// keyed by the program's tids, so the live set has to be too: given the
	// tids /proc shows, a nested target would have every entry pruned.
	if err := c.tracer.PruneDeadTIDs(liveKeys); err != nil {
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
		if tt, ok := totals[pd.key]; pd.keyed && ok {
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

// runqLatency is the run-queue histogram as the tracer has it (#151).
func (c *ThreadsEBPFCollector) runqLatency() (RunqLatency, error) {
	c.mu.Lock()
	tracer := c.tracer
	c.mu.Unlock()
	h, err := tracer.RunqHistogram()
	if err != nil {
		return RunqLatency{}, err
	}
	return RunqLatency{Timestamp: time.Now(), Buckets: append([]uint64(nil), h.Bucket[:]...), Count: h.Count, SumNs: h.SumNs}, nil
}
