package collector

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The rule itself (#199): a match settles it, switches with no match fail it,
// and nothing else concludes anything, an idle target least of all.
func TestJudgeFilter(t *testing.T) {
	for _, c := range []struct {
		matched  bool
		switches uint64
		want     filterVerdict
	}{
		{false, 0, filterUndecided}, // idle: no evidence either way
		{false, filterCheckMinSwitches - 1, filterUndecided},
		{false, filterCheckMinSwitches, filterBlind},
		{false, 1_000_000, filterBlind},
		{true, 0, filterMatches}, // the witness saw it before /proc counted any
		{true, 1_000_000, filterMatches},
	} {
		if got := judgeFilter(c.matched, c.switches); got != c.want {
			t.Errorf("judgeFilter(%v, %d) = %v, want %v", c.matched, c.switches, got, c.want)
		}
	}
}

// The ledger counts what happened between readings, never a thread's past: a
// thread first seen with a million switches brings none of them, and a counter
// read lower than before (a tid reused) adds nothing.
func TestSwitchLedgerCountsOnlyGrowthSinceFirstSeen(t *testing.T) {
	var l switchLedger
	l.add(map[int]uint64{1: 100, 2: 50})
	if l.total != 0 {
		t.Fatalf("baseline counted %d switches, want 0", l.total)
	}
	l.add(map[int]uint64{1: 110, 2: 55, 3: 1_000_000})
	if l.total != 15 {
		t.Fatalf("after growth: %d, want 15 (tid 3 is new and brings nothing)", l.total)
	}
	l.add(map[int]uint64{1: 5, 3: 1_000_004}) // tid 1 reused, tid 2 gone
	if l.total != 19 {
		t.Fatalf("after reuse: %d, want 19", l.total)
	}
}

func TestParseSwitches(t *testing.T) {
	status := "Name:\tptop\nState:\tS (sleeping)\nvoluntary_ctxt_switches:\t1234\nnonvoluntary_ctxt_switches:\t56\n"
	if n, ok := parseSwitches([]byte(status)); !ok || n != 1290 {
		t.Errorf("parseSwitches = %d, %v; want 1290, true", n, ok)
	}
	// One line alone is half the count: refuse it rather than undercount.
	if _, ok := parseSwitches([]byte("voluntary_ctxt_switches:\t1234\n")); ok {
		t.Error("parseSwitches accepted a status with one of the two counters")
	}
	if _, ok := parseSwitches([]byte("voluntary_ctxt_switches:\tx\nnonvoluntary_ctxt_switches:\t1\n")); ok {
		t.Error("parseSwitches accepted a counter that is not a number")
	}
}

// fakeWitness is a filter that has, or has not, matched.
type fakeWitness struct {
	matched atomic.Bool
	err     error
}

func (w *fakeWitness) FilterMatched() (bool, error) { return w.matched.Load(), w.err }

// fakeEvidence is a target whose one thread switches perTick times between
// readings.
type fakeEvidence struct {
	mu      sync.Mutex
	n       uint64
	perTick uint64
}

func (e *fakeEvidence) read() (map[int]uint64, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.n += e.perTick
	return map[int]uint64{42: e.n}, nil
}

func runCheck(t *testing.T, w filterWitness, perTick uint64, ticks int) (*FilterCheckCollector, []string, []interface{}) {
	t.Helper()
	ev := &fakeEvidence{perTick: perTick}
	var mu sync.Mutex
	var fails []string
	c := newFilterCheck(w, SubsystemCPU, "pid 42's threads", ev.read, func(detail string) []ProbeChange {
		mu.Lock()
		fails = append(fails, detail)
		mu.Unlock()
		return []ProbeChange{
			{Status: ProbeStatus{Name: SubsystemCPU, State: ProbeFailed, Detail: detail}},
			{Status: ProbeStatus{Name: SubsystemSyscalls, State: ProbeFailed, Detail: detail}},
		}
	})
	c.interval = 5 * time.Millisecond
	if err := c.Start(42); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Duration(ticks) * c.interval)
	c.Stop()
	var out []interface{}
	for {
		select {
		case v := <-c.Subscribe():
			out = append(out, v)
			continue
		default:
		}
		break
	}
	mu.Lock()
	defer mu.Unlock()
	return c, append([]string(nil), fails...), out
}

func TestFilterCheckFailsABlindFilterOnceWithBothNumbers(t *testing.T) {
	c, fails, out := runCheck(t, &fakeWitness{}, 10, 20)
	if len(fails) != 1 {
		t.Fatalf("fail called %d times, want exactly 1", len(fails))
	}
	if c.Verdict() != filterBlind {
		t.Errorf("verdict %v, want blind", c.Verdict())
	}
	d := fails[0]
	// Two readings of 10 switches each reach the threshold of 20.
	for _, want := range []string{FilterBlindPrefix, "counted 20 context switches", "pid 42's threads", "cpu probe's filter matched 0"} {
		if !strings.Contains(d, want) {
			t.Errorf("detail %q does not say %q", d, want)
		}
	}
	if len(out) != 2 {
		t.Fatalf("published %d values, want the 2 ProbeChanges fail returned", len(out))
	}
	for _, v := range out {
		if pc, ok := v.(ProbeChange); !ok || pc.Status.State != ProbeFailed {
			t.Errorf("published %#v, want a failed ProbeChange", v)
		}
	}
}

func TestFilterCheckStaysSilentForAMatchingFilter(t *testing.T) {
	w := &fakeWitness{}
	w.matched.Store(true)
	c, fails, out := runCheck(t, w, 1000, 20)
	if len(fails) != 0 || len(out) != 0 {
		t.Fatalf("a matching filter failed: %v %v", fails, out)
	}
	if c.Verdict() != filterMatches {
		t.Errorf("verdict %v, want matches", c.Verdict())
	}
}

// An idle target gives no switches, and no switches is no evidence: the check
// must not conclude anything however long it waits.
func TestFilterCheckNeverFailsAnIdleTarget(t *testing.T) {
	c, fails, out := runCheck(t, &fakeWitness{}, 0, 40)
	if len(fails) != 0 || len(out) != 0 {
		t.Fatalf("an idle target failed the filter: %v %v", fails, out)
	}
	if c.Verdict() != filterUndecided {
		t.Errorf("verdict %v, want undecided", c.Verdict())
	}
}

// A witness that cannot be read is no verdict either.
func TestFilterCheckIgnoresAnUnreadableWitness(t *testing.T) {
	_, fails, _ := runCheck(t, &fakeWitness{err: errors.New("closed")}, 1000, 20)
	if len(fails) != 0 {
		t.Fatalf("an unreadable witness failed the filter: %v", fails)
	}
}

// failFilter fails every active eBPF probe behind the filter and leaves alone
// the two that filter on their own pid, the /proc lanes, and probes that were
// not running. io keeps its /proc lane when it has one.
func TestFailFilterTransitions(t *testing.T) {
	s := &Set{IOWait: &IOWaitCollector{}}
	s.probes.active(SubsystemCPU, "eBPF")
	s.probes.active(SubsystemSyscalls, "eBPF")
	s.probes.active(SubsystemIO, "eBPF")
	s.probes.active(SubsystemSignals, "eBPF")
	s.probes.active(SubsystemLifecycle, "eBPF")
	s.probes.active(SubsystemMemory, SourceProc) // the /proc lane: not behind the filter
	s.probes.active(SubsystemFD, SourceProc)
	s.probes.disabled(SubsystemHeap, "--disable heap")

	changes := s.failFilter(FilterBlindPrefix + ": test")
	if !s.filterBlind.Load() {
		t.Error("filterBlind not set")
	}
	got := map[string]ProbeStatus{}
	for _, c := range changes {
		got[c.Status.Name] = c.Status
	}
	if len(got) != 3 {
		t.Errorf("changed %d probes (%v), want cpu, syscalls, io", len(got), got)
	}
	for _, name := range []string{SubsystemCPU, SubsystemSyscalls} {
		if st := got[name]; st.State != ProbeFailed || !strings.HasPrefix(st.Detail, FilterBlindPrefix) {
			t.Errorf("%s: %+v, want failed with the filter's detail", name, st)
		}
	}
	if st := got[SubsystemIO]; st.State != ProbeActive || st.Source != SourceProc || !strings.Contains(st.Detail, FilterBlindPrefix) {
		t.Errorf("io: %+v, want active on /proc with the reason", st)
	}
	want := map[string]ProbeState{
		SubsystemCPU: ProbeFailed, SubsystemSyscalls: ProbeFailed, SubsystemIO: ProbeActive,
		SubsystemSignals: ProbeActive, SubsystemLifecycle: ProbeActive,
		SubsystemMemory: ProbeActive, SubsystemFD: ProbeActive, SubsystemHeap: ProbeDisabled,
	}
	for _, st := range s.Probes() {
		if st.State != want[st.Name] {
			t.Errorf("probe set: %s is %s, want %s", st.Name, st.State, want[st.Name])
		}
	}
}

// What a held-back collector publishes reaches consumers until the filter is
// failed, and nothing after; a collector beside it is untouched.
func TestBusWithholdsAHeldBackCollector(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var blind atomic.Bool
	behind, beside := newFakeCollector(8), newFakeCollector(8)
	bus := NewBus()
	bus.Start(ctx, []Collector{heldBack{behind, &blind}, beside})
	sub := bus.Subscribe(16)
	defer sub.Close()

	behind.ch <- CpuSample{UsagePct: 1}
	if v := recvValue(t, sub); v.(CpuSample).UsagePct != 1 {
		t.Fatalf("got %#v before the verdict, want the sample", v)
	}
	blind.Store(true)
	behind.ch <- CpuSample{UsagePct: 2}
	beside.ch <- SignalEvent{Signal: "SIGTERM"}
	if v := recvValue(t, sub); func() bool { _, ok := v.(SignalEvent); return !ok }() {
		t.Fatalf("got %#v after the verdict, want only the collector beside it", v)
	}
	select {
	case v := <-sub.C():
		t.Fatalf("a withheld value reached the consumer: %#v", v)
	case <-time.After(50 * time.Millisecond):
	}
}
