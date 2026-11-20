package collector

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// ─── A filter that matches nothing says so (#199) ───────────────────────────
//
// Every eBPF probe but signals and lifecycle decides what is the target's with
// one helper, pid_is_target() in target.bpf.h, reading a filter the loader
// resolved. Twice that filter loaded, matched nothing, and every probe reported
// `active` while every axis read zero: #193 (cgroup mode inside a cgroup
// namespace) and #197 (pid mode from an ancestor pid namespace). A zero is a
// measurement, so the capture said a busy process did nothing, and the probe
// states, the one thing a consumer checks, said everything was fine.
//
// So the filter is graded against something outside it, while the capture runs:
//
//   - The witness is the filter itself, at sched_switch: the cpu and threads
//     programs write a map entry the first time pid_is_target() says yes for a
//     task being switched out, and at no other time (FilterMatched).
//   - The evidence is the kernel's count of the same event, kept outside the
//     filter: each of the target's threads' voluntary and involuntary context
//     switches, from /proc/<tid>/status. In cgroup mode the threads are the
//     ones the subtree's cgroup.threads files list.
//
// Every switch /proc counts is a sched_switch with that thread as prev, so a
// filter that matches the target matches it there. /proc counting
// filterCheckMinSwitches of them while the witness is still empty means the
// filter matches nothing, and every probe behind it fails, with both numbers
// (Set.failFilter).
//
// Switches, not CPU time, and that is deliberate. The CPU axis cannot count a
// thread before it has seen it switch out once, so a thread that never switches
// out (a poller pinned to an isolated core) is CPU that /proc counts and the
// probe cannot, with the filter matching fine. Graded on CPU time, that thread
// would fail a working capture. Graded on switches, it is no evidence either
// way. An idle target is the same: no switches, nothing to conclude, and the
// check stays silent for as long as it lasts.
//
// One verdict, then the check stops: the first match settles it for the
// capture, and so does a failure.

// filterCheckMinSwitches is how many context switches /proc must count before
// an empty witness means the filter matches nothing. A filter that matches the
// target matches each of them, so one would do. The margin is for what the
// check cannot see: a switch counted by /proc an instant before the program
// that should match it runs.
const filterCheckMinSwitches = 20

// FilterBlindPrefix starts the detail of every probe the filter check fails,
// so a consumer can tell that failure from an attach error.
const FilterBlindPrefix = "the target filter matches nothing"

// filterCheckInterval is how often the check reads both sides.
const filterCheckInterval = time.Second

type filterVerdict int

const (
	filterUndecided filterVerdict = iota // no evidence yet: idle, or nothing switched
	filterMatches                        // the witness saw the target: settled
	filterBlind                          // /proc saw switches the filter missed
)

// judgeFilter is the whole rule, apart from where the numbers come from.
func judgeFilter(matched bool, switches uint64) filterVerdict {
	switch {
	case matched:
		return filterMatches
	case switches >= filterCheckMinSwitches:
		return filterBlind
	}
	return filterUndecided
}

// filterWitness is a probe whose program records the first time the target
// filter matched (bpf.CPUTracer.FilterMatched, bpf.ThreadsTracer's).
type filterWitness interface {
	FilterMatched() (bool, error)
}

// switchLedger accumulates context switches across readings of every thread's
// counter, keyed by tid. A thread is counted from the reading that first saw
// it, so a thread missed by one reading never brings its whole past in with it;
// one that exits between readings loses only its last interval. Both err
// towards fewer switches, which can only delay a verdict of blind.
type switchLedger struct {
	last  map[int]uint64
	total uint64
}

func (l *switchLedger) add(cur map[int]uint64) {
	for tid, n := range cur {
		if prev, ok := l.last[tid]; ok && n > prev {
			l.total += n - prev
		}
	}
	l.last = cur
}

// FilterCheckCollector grades the target filter once, early in the capture,
// and publishes a ProbeChange for every probe it fails. Context, like
// CostCollector: it measures the capture, not the target, and has no
// --disable name.
type FilterCheckCollector struct {
	witness     filterWitness
	witnessName string                         // the probe the witness belongs to
	scope       string                         // whose switches the evidence counts
	evidence    func() (map[int]uint64, error) // each thread's switches so far
	fail        func(detail string) []ProbeChange
	interval    time.Duration

	ch   chan interface{}
	stop chan struct{}
	once sync.Once
	done chan struct{}

	mu      sync.Mutex
	verdict filterVerdict
}

func newFilterCheck(w filterWitness, witnessName, scope string,
	evidence func() (map[int]uint64, error), fail func(string) []ProbeChange) *FilterCheckCollector {
	return &FilterCheckCollector{
		witness: w, witnessName: witnessName, scope: scope, evidence: evidence, fail: fail,
		interval: filterCheckInterval,
		ch:       make(chan interface{}, 16),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// Start takes the baseline and begins checking. The pid is unused: the
// evidence and the witness were bound when the check was built.
func (c *FilterCheckCollector) Start(int) error {
	var l switchLedger
	if cur, err := c.evidence(); err == nil {
		l.add(cur)
	}
	go c.loop(&l, time.Now())
	return nil
}

func (c *FilterCheckCollector) Stop() {
	c.once.Do(func() { close(c.stop) })
	<-c.done
}

func (c *FilterCheckCollector) Subscribe() <-chan interface{} { return c.ch }

// Verdict says what the check concluded so far.
func (c *FilterCheckCollector) Verdict() filterVerdict {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.verdict
}

func (c *FilterCheckCollector) loop(l *switchLedger, began time.Time) {
	defer close(c.done)
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
		}
		// Evidence first, witness second: every switch this reading counts
		// has run the program by the time the witness is read.
		if cur, err := c.evidence(); err == nil {
			l.add(cur)
		}
		matched, err := c.witness.FilterMatched()
		if err != nil {
			continue
		}
		v := judgeFilter(matched, l.total)
		if v == filterUndecided {
			continue
		}
		c.mu.Lock()
		c.verdict = v
		c.mu.Unlock()
		if v == filterBlind {
			detail := fmt.Sprintf(FilterBlindPrefix+": in %s /proc counted %d context switches of %s, "+
				"and the %s probe's filter matched 0 of them. Every probe behind that filter (all but signals and "+
				"lifecycle) has seen nothing of the target since it attached, so its zeros were not measurements; "+
				"its events are withheld from here on (#199)",
				time.Since(began).Round(time.Second), l.total, c.scope, c.witnessName)
			for _, ch := range c.fail(detail) {
				publish(c.ch, ch)
			}
		}
		return
	}
}

// pidThreadSwitches reads the context switches of each of pid's threads so far.
func pidThreadSwitches(pid int) (map[int]uint64, error) {
	dir := fmt.Sprintf("/proc/%d/task", pid)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make(map[int]uint64, len(ents))
	for _, e := range ents {
		tid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if n, ok := readSwitches(filepath.Join(dir, e.Name(), "status")); ok {
			out[tid] = n
		}
	}
	return out, nil
}

// cgroupThreadSwitches reads the context switches of every thread in the
// cgroup subtree rooted at dir, as its cgroup.threads files list them. Those
// files number threads in this process's pid namespace and leave out the ones
// it cannot see, which can only make the count smaller.
func cgroupThreadSwitches(dir string) (map[int]uint64, error) {
	out := map[int]uint64{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == dir {
				return err
			}
			return nil // a cgroup removed mid-walk
		}
		if !d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(filepath.Join(p, "cgroup.threads"))
		if err != nil {
			return nil
		}
		for _, f := range bytes.Fields(b) {
			tid, err := strconv.Atoi(string(f))
			if err != nil || tid <= 0 {
				continue
			}
			if n, ok := readSwitches(fmt.Sprintf("/proc/%d/status", tid)); ok {
				out[tid] = n
			}
		}
		return nil
	})
	return out, err
}

func readSwitches(path string) (uint64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	return parseSwitches(b)
}

// parseSwitches sums voluntary_ctxt_switches and nonvoluntary_ctxt_switches
// from a /proc/<tid>/status. Each is one switch-out of that thread.
func parseSwitches(status []byte) (uint64, bool) {
	var sum uint64
	found := 0
	for _, line := range bytes.Split(status, []byte("\n")) {
		k, v, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		switch string(k) {
		case "voluntary_ctxt_switches", "nonvoluntary_ctxt_switches":
			n, err := strconv.ParseUint(string(bytes.TrimSpace(v)), 10, 64)
			if err != nil {
				return 0, false
			}
			sum += n
			found++
		}
	}
	return sum, found == 2
}
