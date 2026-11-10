//go:build linux && ebpf

package main

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/trentas/ptop/internal/bpf"
	"github.com/trentas/ptop/pkg/collector"
)

// The cases in this file grade what a COLLECTOR publishes — the value the wire
// carries — rather than the raw tracer underneath it. The bugs they guard
// against lived in the collectors: a call site cut before its stacks were
// folded (#109), a syscall left unnamed and its latency dropped (#139), a
// heap snapshot thrown away on the collector's own channel (#121). A tracer
// read would have passed every one of them.

// zBand is how many standard deviations a sampled share may stray from the
// planted one before the grade fails. At 4 a correct axis fails a given check
// about once in 16,000 runs; a wrong one (a share off by a factor, a function
// missing) misses by far more.
const zBand = 4

// shareBand is the half-width, in percentage points, of the zBand interval
// around share p (a fraction) for n independent samples.
func shareBand(p float64, n uint64) float64 {
	if n == 0 {
		return math.Inf(1)
	}
	return zBand * math.Sqrt(p*(1-p)/float64(n)) * 100
}

// collect starts c on pid, runs workload, waits settle so the window holding
// the workload's end is published, and returns every value c published, in
// order.
func collect(c collector.Collector, pid int, settle time.Duration, workload func()) ([]any, error) {
	if err := c.Start(pid); err != nil {
		return nil, err
	}
	ch := c.Subscribe()
	var (
		mu   sync.Mutex
		vals []any
	)
	done, drained := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(drained)
		for {
			select {
			case v := <-ch:
				mu.Lock()
				vals = append(vals, v)
				mu.Unlock()
			case <-done:
				return
			}
		}
	}()
	workload()
	time.Sleep(settle)
	close(done)
	<-drained
	c.Stop()
	return vals, nil
}

// quietThread runs f on a thread of its own with every signal blocked, and
// restores the mask before releasing the thread.
//
// A signal that lands on a blocking planted call changes what the call is: a
// sleep or a timed futex wait ends early with EINTR and has to be re-issued (one
// more real call). The Go runtime sends SIGURG to its own threads for
// preemption, most of all during a GC, so without this an exact count holds
// only when no signal happened to arrive — measured once in CI, 31 reads for
// 30, before the axes counted a call the kernel re-runs once (#160, #164). The
// restart case plants the signals on purpose instead.
func quietThread(f func()) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var all, old unix.Sigset_t
	for i := range all.Val {
		all.Val[i] = ^uint64(0)
	}
	if err := unix.PthreadSigmask(unix.SIG_BLOCK, &all, &old); err == nil {
		defer func() { _ = unix.PthreadSigmask(unix.SIG_SETMASK, &old, nil) }()
	}
	f()
}

// ─── cpuprof: a planted 60/30/10 split (#125) ───────────────────────────────

// The three burners are identical but for their names, so any difference in
// what the axis attributes to them comes from the time each was given. Each
// body is call-free arithmetic with the deadline checked every few tens of
// microseconds, so the clock read is a rounding error in the leaf counts.

var cpuSplitSink uint64

//go:noinline
func plantedSixty(until time.Time) uint64 {
	var acc uint64
	for time.Now().Before(until) {
		for i := 0; i < 20_000; i++ {
			acc = acc*1664525 + 1013904223
		}
	}
	return acc
}

//go:noinline
func plantedThirty(until time.Time) uint64 {
	var acc uint64
	for time.Now().Before(until) {
		for i := 0; i < 20_000; i++ {
			acc = acc*1664525 + 1013904223
		}
	}
	return acc
}

//go:noinline
func plantedTen(until time.Time) uint64 {
	var acc uint64
	for time.Now().Before(until) {
		for i := 0; i < 20_000; i++ {
			acc = acc*1664525 + 1013904223
		}
	}
	return acc
}

// plantCPUSplit burns d of one thread, split 60/30/10 between the burners.
//
// Each cycle has a random length. A fixed-period workload sampled at a nearby
// fixed rate lands on the same phase of every cycle and splits the samples by
// phase, not by time — the aliasing the 99Hz default insures against (#125). A
// random cycle has no phase to lock to, so the expected split is the planted
// one whatever the sampler's period.
func plantCPUSplit(d time.Duration) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	r := rand.New(rand.NewPCG(155, 6030)) // fixed: a failure reproduces
	deadline := time.Now().Add(d)
	for now := time.Now(); now.Before(deadline); now = time.Now() {
		cycle := time.Duration(4_000+r.IntN(12_000)) * time.Microsecond
		t := now.Add(cycle * 6 / 10)
		cpuSplitSink += plantedSixty(t)
		t = t.Add(cycle * 3 / 10)
		cpuSplitSink += plantedThirty(t)
		t = t.Add(cycle / 10)
		cpuSplitSink += plantedTen(t)
	}
}

// spreadBurn is one function per type argument: each GC shape gets a stenciled
// body and a symbol of its own (main.spreadBurn[go.shape.int8], …). That is the
// cheapest way to have more hot functions than the profile lists, which the
// census check needs and the 60/30/10 split never produces.
//
//go:noinline
func spreadBurn[T any](until time.Time) uint64 {
	var acc uint64
	for time.Now().Before(until) {
		for i := 0; i < 20_000; i++ {
			acc = acc*1664525 + 1013904223
		}
	}
	return acc
}

var spreadBurners = []func(time.Time) uint64{
	spreadBurn[int8], spreadBurn[int16], spreadBurn[int32], spreadBurn[int64],
	spreadBurn[uint8], spreadBurn[uint16], spreadBurn[uint32], spreadBurn[uint64],
	spreadBurn[float32], spreadBurn[float64], spreadBurn[complex64], spreadBurn[complex128],
}

// plantCPUSpread burns d of one thread over the spread burners, a random one
// for a random slice each time.
//
// Not round-robin: twelve fixed 1ms slices make a 12ms cycle, and a ~10ms
// sampler stepping through it lands on every other burner and never the rest —
// measured, six of the twelve took all the samples. The same aliasing as in
// plantCPUSplit, found by this case before the random draw went in.
func plantCPUSpread(d time.Duration) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	r := rand.New(rand.NewPCG(155, 12))
	deadline := time.Now().Add(d)
	for now := time.Now(); now.Before(deadline); now = time.Now() {
		slice := time.Duration(500+r.IntN(1000)) * time.Microsecond
		cpuSplitSink += spreadBurners[r.IntN(len(spreadBurners))](now.Add(slice))
	}
}

// cpuCensus checks, window by window, that every sample is in exactly one
// place: a listed site, the unresolved bucket, or the volume the top-N cut
// omitted. A window where they do not add up has lost or invented samples, and
// its shares are wrong by that much.
type cpuCensus struct {
	windows, bad, cut int
	firstMiss         string
}

func (c *cpuCensus) add(p collector.CPUProfile) {
	c.windows++
	var listed uint64
	for _, s := range p.Sites {
		listed += s.Samples
	}
	if p.TotalSites > uint32(len(p.Sites)) {
		c.cut++
	}
	if sum := listed + p.UnresolvedSamples + p.OmittedSamples; sum != p.TotalSamples {
		c.bad++
		if c.firstMiss == "" {
			c.firstMiss = fmt.Sprintf("; first miss: %d listed + %d unresolved + %d omitted = %d, total says %d",
				listed, p.UnresolvedSamples, p.OmittedSamples, sum, p.TotalSamples)
		}
	}
}

func checkCPUProfile(g *grader, pid int) {
	const burn = 5 * time.Second
	c := collector.NewCPUProfEBPFCollector(bpf.CPUProfDefaultHz, nil)
	vals, err := collect(c, pid, 1500*time.Millisecond, func() { plantCPUSplit(burn) })
	if err != nil {
		g.broken("cpuprof", "attach", err)
		return
	}

	planted := []struct {
		fn    string
		share float64
	}{
		{"main.plantedSixty", 0.6},
		{"main.plantedThirty", 0.3},
		{"main.plantedTen", 0.1},
	}

	var census cpuCensus
	var total uint64
	byFunc := make(map[string]uint64)
	for _, v := range vals {
		p, ok := v.(collector.CPUProfile)
		if !ok {
			continue
		}
		census.add(p)
		for _, s := range p.Sites {
			byFunc[s.Func] += s.Samples
		}
		total += p.TotalSamples
	}
	if !g.check("cpuprof", "windows published", census.windows > 0, "> 0", fmt.Sprint(census.windows)) {
		return
	}

	var n uint64
	for _, p := range planted {
		n += byFunc[p.fn]
	}
	// Below this the interval around the 10% share is wider than the share
	// itself, and a grade would pass anything. 5s at 99Hz delivers ~495.
	const minSamples = 300
	if g.check("cpuprof", fmt.Sprintf("samples in the planted functions over %v", burn), n >= minSamples,
		fmt.Sprintf(">= %d", minSamples), fmt.Sprint(n)) {
		// The planted functions are all the target burned. What lands elsewhere
		// is the runtime's background work and the windows either side of the
		// burn.
		inPlanted := float64(n) / float64(total) * 100
		g.check("cpuprof", "share of all samples in the planted functions", inPlanted >= 90,
			">= 90%", fmt.Sprintf("%.1f%% (%d of %d)", inPlanted, n, total))

		for _, p := range planted {
			got := float64(byFunc[p.fn]) / float64(n) * 100
			band := shareBand(p.share, n)
			want := p.share * 100
			g.check("cpuprof", fmt.Sprintf("%s share of the planted samples", p.fn), math.Abs(got-want) <= band,
				fmt.Sprintf("%.0f%% ±%.1f (%dσ, n=%d)", want, band, zBand, n),
				fmt.Sprintf("%.1f%% (%d samples)", got, byFunc[p.fn]))
		}
		a, b, c3 := byFunc[planted[0].fn], byFunc[planted[1].fn], byFunc[planted[2].fn]
		g.check("cpuprof", "ranking", a > b && b > c3, "sixty > thirty > ten",
			fmt.Sprintf("%d / %d / %d samples", a, b, c3))
	}

	// Second burn: more hot functions than the profile lists, so the cut
	// applies and the omitted count carries real samples. Without it the census
	// below would only ever see omitted == 0, and pass by vacuity.
	c = collector.NewCPUProfEBPFCollector(bpf.CPUProfDefaultHz, nil)
	spread, err := collect(c, pid, 1500*time.Millisecond, func() { plantCPUSpread(2 * time.Second) })
	if err != nil {
		g.broken("cpuprof", "attach (spread burn)", err)
		return
	}
	cutBefore := census.cut
	for _, v := range spread {
		if p, ok := v.(collector.CPUProfile); ok {
			census.add(p)
		}
	}
	g.check("cpuprof", fmt.Sprintf("spread burn over %d functions: windows where the list was cut", len(spreadBurners)),
		census.cut > cutBefore, ">= 1", fmt.Sprint(census.cut-cutBefore))
	g.check("cpuprof", "every window's sites + unresolved + omitted = its total", census.bad == 0,
		fmt.Sprintf("%d of %d", census.windows, census.windows),
		fmt.Sprintf("%d of %d%s", census.windows-census.bad, census.windows, census.firstMiss))
}

// ─── syscalls: a known count, a known latency (#139) ────────────────────────

func checkSyscalls(g *grader, pid int) {
	// Both syscalls are ones nothing else in a Go process makes, so the counts
	// are exact. nanosleep would not do: the runtime's sysmon sleeps with it,
	// dozens of times a second.
	const (
		quick = 5000 // getppid(2)
		naps  = 20   // clock_nanosleep(2), which blocks for at least the time asked
		nap   = 5 * time.Millisecond
	)
	c := collector.NewSyscallsEBPFCollector()
	vals, err := collect(c, pid, 700*time.Millisecond, func() {
		for i := 0; i < quick; i++ {
			_ = unix.Getppid()
		}
		quietThread(func() {
			ts := unix.NsecToTimespec(int64(nap))
			for i := 0; i < naps; i++ {
				_ = unix.ClockNanosleep(unix.CLOCK_MONOTONIC, 0, &ts, nil)
			}
		})
	})
	if err != nil {
		g.broken("syscalls", "attach", err)
		return
	}
	// The snapshot is cumulative since attach, so the last one holds every
	// call that returned.
	var last []collector.SyscallEvent
	for _, v := range vals {
		if s, ok := v.([]collector.SyscallEvent); ok {
			last = s
		}
	}
	rows := make(map[string]collector.SyscallEvent, len(last))
	for _, r := range last {
		rows[r.Name] = r
	}

	gp, ok := rows["getppid"]
	if g.check("syscalls", "getppid has a named row (#139)", ok, "a row", rowOrNames(ok, last)) {
		g.check("syscalls", "getppid count", gp.Count == quick, fmt.Sprintf("exactly %d", quick), fmt.Sprint(gp.Count))
		mean := time.Duration(0)
		if gp.Count > 0 {
			mean = time.Duration(gp.LatencyNs / gp.Count)
		}
		// Measured, not exported as 0 (#139), and a call that does not block
		// costs well under a hundred microseconds even with the probe's own
		// overhead inside it.
		g.check("syscalls", "getppid mean latency", mean > 0 && mean < 100*time.Microsecond,
			"(0, 100µs)", mean.String())
	}

	ns, ok := rows["clock_nanosleep"]
	if g.check("syscalls", "clock_nanosleep has a named row", ok, "a row", rowOrNames(ok, last)) {
		g.check("syscalls", "clock_nanosleep count", ns.Count == naps, fmt.Sprintf("exactly %d", naps), fmt.Sprint(ns.Count))
		// The floor is the sleep asked for. The ceiling is twice that: a timer
		// that late is broken rather than loaded, and it is also what a latency
		// counted twice — entry and exit both accounted — would read.
		lat := time.Duration(ns.LatencyNs)
		lo, hi := naps*nap, 2*naps*nap
		g.check("syscalls", fmt.Sprintf("clock_nanosleep latency summed over %d naps of %v", naps, nap),
			lat >= lo && lat <= hi, fmt.Sprintf("[%v, %v]", lo, hi), round(lat).String())
	}
}

// rowOrNames says what a lookup by name found, and on a miss what the rows
// were called instead — an unnamed syscall shows up as its number.
func rowOrNames(found bool, rows []collector.SyscallEvent) string {
	if found {
		return "a row"
	}
	names := make([]string, 0, 8)
	for i, r := range rows {
		if i == 8 {
			break
		}
		names = append(names, r.Name)
	}
	return "none (busiest rows: " + strings.Join(names, ", ") + ")"
}

// ─── futex: waits on a known word, from a known function ────────────────────

// plantedFutexWord is the lock. Its address is the identity the axis keys on.
var plantedFutexWord uint32

const futexWaitPrivate = 0 | 128 // FUTEX_WAIT | FUTEX_PRIVATE_FLAG
const futexWakePrivate = 1 | 128 // FUTEX_WAKE | FUTEX_PRIVATE_FLAG

// plantedFutexWait blocks on plantedFutexWord until the timeout. Nobody wakes
// it, so every call is one wait of exactly the timeout, at least.
//
//go:noinline
func plantedFutexWait(timeout time.Duration) {
	ts := unix.NsecToTimespec(int64(timeout))
	_, _, _ = unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(&plantedFutexWord)), futexWaitPrivate,
		0, uintptr(unsafe.Pointer(&ts)), 0, 0)
}

func checkFutex(g *grader, pid int) {
	const (
		threads = 4
		waits   = 100 // per thread
		timeout = 5 * time.Millisecond
	)
	c := collector.NewFutexEBPFCollector(nil)
	vals, err := collect(c, pid, 2200*time.Millisecond, func() {
		var wg sync.WaitGroup
		for i := 0; i < threads; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				quietThread(func() {
					for j := 0; j < waits; j++ {
						plantedFutexWait(timeout)
					}
				})
			}()
		}
		wg.Wait()
	})
	if err != nil {
		g.broken("futex", "attach", err)
		return
	}

	// Waiters is cumulative, so the largest count seen is the whole run.
	addr := uint64(uintptr(unsafe.Pointer(&plantedFutexWord)))
	var best collector.LockEntry
	found := false
	for _, v := range vals {
		snap, ok := v.([]collector.LockEntry)
		if !ok {
			continue
		}
		for _, e := range snap {
			if e.UAddr == addr && (!found || e.Waiters > best.Waiters) {
				best, found = e, true
			}
		}
	}
	if !g.check("futex", fmt.Sprintf("the planted word (%#x) is in the lock graph", addr), found,
		"a row", rowFound(found)) {
		return
	}
	g.check("futex", "waits on it", best.Waiters == threads*waits,
		fmt.Sprintf("exactly %d (%d threads × %d)", threads*waits, threads, waits), fmt.Sprint(best.Waiters))
	// Each wait sleeps the full timeout: nobody wakes it. The ceiling is a
	// wake late by the timeout again, which no working timer produces.
	got := time.Duration(best.LatencyMs * float64(time.Millisecond))
	g.check("futex", "mean wait", got >= timeout && got <= 2*timeout,
		fmt.Sprintf("[%v, %v]", timeout, 2*timeout), got.Round(10*time.Microsecond).String())
	name := best.Func
	if name == "" {
		name = "no symbol"
	}
	g.check("futex", "the lock is named by the function that waited (#89)", best.Func == "main.plantedFutexWait",
		"main.plantedFutexWait", name)
}

func rowFound(found bool) string {
	if found {
		return "a row"
	}
	return "none"
}

// ─── goalloc: two call sites at a known rate and a known ratio (#108, #109) ─

// heapSink makes every planted allocation escape, so it is a real mallocgc.
var heapSink []byte

const plantedAllocSize = 16 << 10

//go:noinline
func plantedAllocMajor() { heapSink = make([]byte, plantedAllocSize) }

//go:noinline
func plantedAllocMinor() { heapSink = make([]byte, plantedAllocSize) }

// plantedAllocSpread is one call site per type argument (see spreadBurn): more
// sites than the top list holds, so the cut applies and the omitted totals
// carry real volume.
//
//go:noinline
func plantedAllocSpread[T any]() { heapSink = make([]byte, plantedAllocSize) }

var spreadAllocators = []func(){
	plantedAllocSpread[int8], plantedAllocSpread[int16], plantedAllocSpread[int32], plantedAllocSpread[int64],
	plantedAllocSpread[uint8], plantedAllocSpread[uint16], plantedAllocSpread[uint32], plantedAllocSpread[uint64],
	plantedAllocSpread[float32], plantedAllocSpread[float64], plantedAllocSpread[complex64], plantedAllocSpread[complex128],
}

func checkGoAlloc(g *grader, pid int) {
	const (
		rate   = 128 << 20 // bytes/s, planted
		tick   = 10 * time.Millisecond
		run    = 4 * time.Second
		pMajor = 0.75
	)
	perTick := int(rate / plantedAllocSize * int(tick) / int(time.Second))
	// The rate that ships. 0 here would be every allocation: the constructor
	// does not fill in the default the way SetConfig does.
	c := collector.NewHeapEBPFCollector(bpf.GoAllocDefaultSampleBytes, nil)
	var start, end time.Time
	var major, minor uint64
	vals, err := collect(c, pid, 1200*time.Millisecond, func() {
		r := rand.New(rand.NewPCG(155, 109))
		start = time.Now()
		next := start
		for next.Before(start.Add(run)) {
			for i := 0; i < perTick; i++ {
				if r.Float64() < pMajor {
					plantedAllocMajor()
					major++
				} else {
					plantedAllocMinor()
					minor++
				}
			}
			next = next.Add(tick)
			time.Sleep(time.Until(next))
		}
		end = time.Now()
		// After the rate windows, so it does not move the planted rate: 4 MiB
		// from each spread site, ~8 samples apiece at the default rate.
		for _, alloc := range spreadAllocators {
			for i := 0; i < (4<<20)/plantedAllocSize; i++ {
				alloc()
			}
		}
	})
	if err != nil {
		g.broken("goalloc", "attach", err)
		return
	}

	var last collector.HeapStats
	var rates []float64
	for _, v := range vals {
		h, ok := v.(collector.HeapStats)
		if !ok {
			continue
		}
		last = h
		// A window is (previous publish, this one]; only those wholly inside
		// the workload measure its rate.
		if h.Timestamp.After(start.Add(time.Second)) && !h.Timestamp.After(end) {
			rates = append(rates, h.AllocBytesRate)
		}
	}
	if !g.check("goalloc", "the Go lane published", last.Lane == collector.HeapLaneGo,
		"lane "+collector.HeapLaneGo, "lane "+fmt.Sprintf("%q", last.Lane)) {
		return
	}

	// The rate is exact on this lane — totals are counted, only the per-site
	// split is sampled — so the band is the pacing jitter plus the rest of this
	// process (the collector itself allocates), not sampling error.
	if g.check("goalloc", "windows wholly inside the workload", len(rates) >= 2, ">= 2", fmt.Sprint(len(rates))) {
		sort.Float64s(rates)
		med := rates[len(rates)/2]
		g.check("goalloc", "alloc rate (median window)", math.Abs(med-rate) <= rate*0.15,
			fmt.Sprintf("%s ±15%%", mib(rate)), mib(med))
	}

	sites := make(map[string]collector.HeapCallSite, len(last.TopCallSites))
	for _, s := range last.TopCallSites {
		sites[s.Func] = s
	}
	ma, okA := sites["main.plantedAllocMajor"]
	mi, okB := sites["main.plantedAllocMinor"]
	g.check("goalloc", "both planted call sites in the top list", okA && okB,
		"main.plantedAllocMajor and main.plantedAllocMinor", topFuncs(last.TopCallSites))

	// The census contract (#109): the list is complete exactly when the counts
	// agree, and otherwise the omitted volume is what says so. The spread sites
	// make sure it is the second half that gets checked.
	listed := uint32(len(last.TopCallSites))
	g.check("goalloc", fmt.Sprintf("spread over %d more call sites: the list was cut", len(spreadAllocators)),
		last.TotalCallSites > listed, fmt.Sprintf("more than %d sites", listed), fmt.Sprint(last.TotalCallSites))
	omitted := last.OmittedAllocCount + last.OmittedAllocBytes
	consistent := last.TotalCallSites >= listed && (last.TotalCallSites == listed) == (omitted == 0)
	g.check("goalloc", "census: omitted volume is zero exactly when the list is complete", consistent,
		"total_call_sites == listed ⟺ omitted == 0",
		fmt.Sprintf("total %d, listed %d, omitted %d allocs / %s", last.TotalCallSites, listed,
			last.OmittedAllocCount, mib(float64(last.OmittedAllocBytes))))

	if !okA || !okB {
		return
	}
	// Per-site bytes are an estimate: each recorded sample is credited with
	// everything allocated since the previous one, and the threshold is drawn
	// at random around SampleBytes. So the split behaves like a binomial over
	// the number of samples taken, widened by the spread of the credits (a
	// uniform threshold has a coefficient of variation of 1/√3, hence 1.15).
	plantedBytes := float64(major+minor) * plantedAllocSize
	sb := float64(last.SampleBytes)
	if sb == 0 {
		sb = 1
	}
	n := uint64(plantedBytes / sb)
	est := float64(ma.AllocBytes) + float64(mi.AllocBytes)
	gotShare := float64(ma.AllocBytes) / est * 100
	trueShare := float64(major) / float64(major+minor) * 100
	band := shareBand(trueShare/100, n) * 1.15
	g.check("goalloc", "major site's share of the planted bytes", math.Abs(gotShare-trueShare) <= band,
		fmt.Sprintf("%.1f%% ±%.1f (%dσ, ~%d samples of %s)", trueShare, band, zBand, n, mib(sb)),
		fmt.Sprintf("%.1f%% (%s of %s)", gotShare, mib(float64(ma.AllocBytes)), mib(est)))
	// And the two together account for what was planted: the sum of credits
	// is the exact total, less the tail after the last sample and whatever the
	// rest of the process allocated in between.
	g.check("goalloc", "planted sites' estimated bytes", math.Abs(est-plantedBytes) <= plantedBytes*0.1,
		fmt.Sprintf("%s ±10%%", mib(plantedBytes)), mib(est))
}

func mib(b float64) string { return fmt.Sprintf("%.1f MiB", b/(1<<20)) }

func topFuncs(sites []collector.HeapCallSite) string {
	names := make([]string, 0, len(sites))
	for _, s := range sites {
		n := s.Func
		if n == "" {
			n = s.AddrHex
		}
		names = append(names, n)
	}
	return strings.Join(names, ", ")
}

// ─── io: reads that block for a known time ──────────────────────────────────

// checkIO plants reads whose latency is known: each one waits on a pipe until
// another goroutine writes, which it does every ioDelay. The pipe is a raw,
// BLOCKING one. os.Pipe would not do: Go puts it in non-blocking mode under the
// netpoller, so the read returns EAGAIN at once and the wait happens in
// epoll_pwait, where this axis does not look.
//
// The writer is a thread of its own sleeping in clock_nanosleep, not a goroutine
// in time.Sleep. A Go timer can fire late: while the reader holds its P inside
// the syscall, a timer on that P waits for sysmon to retake it, and an idle
// sysmon sleeps up to 10ms — one planted 10ms read measured over 20ms that way.
//
// Then, on every CPU this process may run on, a thread pinned there writes a
// file of its own and unlinks files of its own. A probe that only runs on some
// CPUs drops whatever the target did on the others, and an unpinned workload
// reads that as a random fraction of writes going missing (#159). Pinned, the
// miss names the CPU.
func checkIO(g *grader, pid int) {
	const (
		reads   = 30
		ioDelay = 10 * time.Millisecond // mid-bucket: 5-20ms either side of any reasonable jitter
		perCPU  = 20                    // writes, and unlinks, planted on each CPU
	)
	cpus, err := allowedCPUs()
	if err != nil {
		g.broken("io", "the CPUs this process may run on", err)
		return
	}
	dir, err := os.MkdirTemp("", "ptop-selftest-io-")
	if err != nil {
		g.broken("io", "a scratch directory", err)
		return
	}
	defer os.RemoveAll(dir)
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC); err != nil {
		g.broken("io", "pipe", err)
		return
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	var st unix.Stat_t
	if err := unix.Fstat(fds[0], &st); err != nil {
		g.broken("io", "fstat the pipe", err)
		return
	}
	pipePath := fmt.Sprintf("pipe:[%d]", st.Ino) // what /proc/<pid>/fd links it as

	var pinErr error
	var held []int // the per-CPU files' fds, closed once the collector has stopped
	c := collector.NewIOEBPFCollector()
	vals, err := collect(c, pid, 700*time.Millisecond, func() {
		done := make(chan struct{})
		go func() {
			defer close(done)
			quietThread(func() {
				nap := unix.NsecToTimespec(int64(ioDelay))
				for i := 0; i < reads; i++ {
					_ = unix.ClockNanosleep(unix.CLOCK_MONOTONIC, 0, &nap, nil)
					_, _ = unix.Write(fds[1], []byte{1})
				}
			})
		}()
		quietThread(func() {
			buf := make([]byte, 1)
			for i := 0; i < reads; i++ {
				_, _ = unix.Read(fds[0], buf)
			}
		})
		<-done

		// The collector names a file by reading /proc/<pid>/fd/<n> when it
		// processes the event, and remembers the answer by fd NUMBER for a
		// couple of seconds. So every file written here is opened before any
		// is written and stays open until the collector stops: a file closed
		// by then reads as "fd=N", and a number reused within the cache's
		// lifetime is credited to the file that held it before.
		for _, cpu := range cpus {
			fd, err := unix.Open(writePath(dir, cpu), unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC, 0o600)
			if err != nil {
				pinErr = fmt.Errorf("cpu %d: open: %w", cpu, err)
				return
			}
			held = append(held, fd)
		}
		for i, cpu := range cpus {
			for j := 0; j < perCPU; j++ {
				// open+close and nothing else: os.WriteFile would issue a
				// zero-length write(2) on the way.
				if fd, err := unix.Open(unlinkPath(dir, cpu, j), unix.O_WRONLY|unix.O_CREAT|unix.O_CLOEXEC, 0o600); err == nil {
					_ = unix.Close(fd)
				}
			}
			fd := held[i]
			if err := onCPU(cpu, func() {
				for j := 0; j < perCPU; j++ {
					_, _ = unix.Write(fd, []byte{1})
				}
				for j := 0; j < perCPU; j++ {
					_ = unix.Unlinkat(unix.AT_FDCWD, unlinkPath(dir, cpu, j), 0)
				}
			}); err != nil && pinErr == nil {
				pinErr = fmt.Errorf("cpu %d: %w", cpu, err)
			}
		}
	})
	for _, fd := range held {
		_ = unix.Close(fd)
	}
	if err != nil {
		g.broken("io", "attach", err)
		return
	}
	if pinErr != nil {
		g.broken("io", "pin a thread to each CPU", pinErr)
		return
	}

	// The histogram resets every window; the file rows are cumulative.
	buckets := make(map[string]collector.LatencyBucket)
	var row collector.IOFileStats
	found := false
	writes := make(map[string]uint64) // path → writes; rows are cumulative, the last wins
	deleted := make(map[string]bool)
	for _, v := range vals {
		switch v := v.(type) {
		case collector.IOEBPFSnapshot:
			for _, b := range v.Buckets {
				acc := buckets[b.Label]
				acc.Read += b.Read
				acc.Write += b.Write
				buckets[b.Label] = acc
			}
			for _, f := range v.TopFiles {
				if f.Path == pipePath {
					row, found = f, true
				}
				writes[f.Path] = f.Writes
			}
		case collector.FSEvent:
			if v.Op == "deleted" {
				deleted[v.Path] = true
			}
		}
	}
	if g.check("io", "the pipe has a row, by its /proc path", found, pipePath, rowFound(found)) {
		g.check("io", "reads on it", row.Reads == reads, fmt.Sprint(reads), fmt.Sprint(row.Reads))
	}
	// The histogram is the whole process's, so other reads could land in it;
	// nothing else this process does blocks for 5-20ms, which makes the
	// planted reads the whole of that bucket.
	g.check("io", fmt.Sprintf("reads in the 5-20ms bucket (%d planted at %v)", reads, ioDelay),
		buckets["5-20ms"].Read == reads, fmt.Sprint(reads), readHistogram(buckets))

	for _, cpu := range cpus {
		w := writes[writePath(dir, cpu)]
		g.check("io", fmt.Sprintf("writes made on CPU %d (#159)", cpu), w == perCPU, fmt.Sprint(perCPU), fmt.Sprint(w))
		n := 0
		for i := 0; i < perCPU; i++ {
			if deleted[unlinkPath(dir, cpu, i)] {
				n++
			}
		}
		g.check("io", fmt.Sprintf("unlinks made on CPU %d, as fs events (#159)", cpu), n == perCPU,
			fmt.Sprint(perCPU), fmt.Sprint(n))
	}
}

func writePath(dir string, cpu int) string     { return fmt.Sprintf("%s/w%d", dir, cpu) }
func unlinkPath(dir string, cpu, i int) string { return fmt.Sprintf("%s/u%d-%d", dir, cpu, i) }

// allowedCPUs lists the CPUs this process may be scheduled on.
func allowedCPUs() ([]int, error) {
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(0, &set); err != nil {
		return nil, err
	}
	var cpus []int
	for i := 0; i < len(set)*64; i++ {
		if set.IsSet(i) {
			cpus = append(cpus, i)
		}
	}
	return cpus, nil
}

// onCPU runs f on a signal-quiet thread pinned to cpu, and gives the thread its
// previous affinity back before releasing it.
func onCPU(cpu int, f func()) error {
	var err error
	quietThread(func() {
		var prev, only unix.CPUSet
		if err = unix.SchedGetaffinity(0, &prev); err != nil {
			return
		}
		only.Set(cpu)
		if err = unix.SchedSetaffinity(0, &only); err != nil {
			return
		}
		defer func() { _ = unix.SchedSetaffinity(0, &prev) }()
		f()
	})
	return err
}

// readHistogram renders the summed read histogram, in bucket order.
func readHistogram(b map[string]collector.LatencyBucket) string {
	order := []string{"<0.1ms", "0.1-1ms", "1-5ms", "5-20ms", ">20ms"}
	parts := make([]string, 0, len(order))
	for _, l := range order {
		parts = append(parts, fmt.Sprintf("%s:%g", l, b[l].Read))
	}
	return strings.Join(parts, " ")
}

// ─── blind must say blind (#112) ────────────────────────────────────────────

// checkBlind starts a Set in which nothing can observe: heap switched off by
// name, TLS asked for against a target with no libssl (this binary is static),
// everything else switched off. Both kinds of blindness have to be SAID, in the
// probe set a consumer reads before it reads any number, and neither may
// produce a value that looks like a quiet target.
func checkBlind(g *grader, pid int) {
	// The accepted --disable names ARE the subsystem list; reading it from there
	// means a subsystem added later is covered without editing this case.
	all := strings.Split(collector.KnownSubsystems(), ", ")
	disable := make(map[string]bool)
	for _, name := range all {
		if name != collector.SubsystemTLS {
			disable[name] = true
		}
	}
	s := collector.NewSet(collector.SetConfig{PID: pid, Disable: disable, TLS: true})
	defer s.Stop()

	statuses := make(map[string]collector.ProbeStatus)
	for _, st := range s.Probes() {
		statuses[st.Name] = st
	}
	var missing []string
	for _, name := range all {
		if _, ok := statuses[name]; !ok {
			missing = append(missing, name)
		}
	}
	got := fmt.Sprint(len(all) - len(missing))
	if len(missing) > 0 {
		got += " (missing: " + strings.Join(missing, ", ") + ")"
	}
	g.check("blind", "every subsystem has a status in the probe set", len(missing) == 0,
		fmt.Sprintf("all %d", len(all)), got)

	heap := statuses[collector.SubsystemHeap]
	g.check("blind", "heap, switched off by name", heap.State == collector.ProbeDisabled && heap.Detail != "",
		"disabled, with the reason", fmt.Sprintf("%s (%q)", heap.State, heap.Detail))
	tls := statuses[collector.SubsystemTLS]
	g.check("blind", "tls, asked for with no libssl to attach to", tls.State == collector.ProbeFailed && tls.Detail != "",
		"failed, with the error", fmt.Sprintf("%s (%q)", tls.State, tls.Detail))

	// Nothing is attached, so nothing may publish a measurement: a value here
	// would read as a target nobody was watching. The exceptions are context,
	// not any probe's reading of the target, and have no --disable name:
	// ProcContext, the target's identity (namespaces, cgroup, ids), and
	// HostSample, the host's steal and the target cgroup's limits (#153).
	//
	// The handler goes on before the bus starts draining, so a value published
	// in the first instant is not missed.
	ctx, cancel := context.WithCancel(context.Background())
	bus := collector.NewBus()
	var mu sync.Mutex
	var seen []string
	h := bus.AddHandler(func(v any) {
		switch v.(type) {
		case collector.ProcContext, collector.HostSample:
			return
		}
		mu.Lock()
		seen = append(seen, fmt.Sprintf("%T", v))
		mu.Unlock()
	})
	bus.Start(ctx, s.Collectors())
	time.Sleep(1500 * time.Millisecond)
	bus.RemoveHandler(h)
	cancel()
	mu.Lock()
	defer mu.Unlock()
	got = fmt.Sprint(len(seen))
	if len(seen) > 0 {
		got += " (" + strings.Join(firstN(seen, 5), ", ") + ")"
	}
	g.check("blind", "measurements published in 1.5s by a Set with nothing attached", len(seen) == 0, "0", got)
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
