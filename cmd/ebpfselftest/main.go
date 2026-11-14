//go:build linux && ebpf

// ebpf-selftest grades ptop's eBPF axes against workloads whose answer is
// known (#155). Run as root:
//
//	sudo ./bin/ebpf-selftest            every case
//	sudo ./bin/ebpf-selftest -list      what the cases are
//	sudo ./bin/ebpf-selftest -run cpu,net
//
// It targets its own process, plants a behaviour on one axis at a time, and
// checks the VALUE the axis reports against the planted one — a counter that
// moves is not the same as a counter that is right (#108). Peers that must
// live in another process (the network axis, #135) are this binary
// re-executed. Every reading prints the axis, the claim, what was expected and
// what was measured, so a regression names the axis and the size of the miss.
//
// Exit code is 0 when every graded reading passed, 1 when any failed, 2 for a
// bad -run. CI runs it on amd64 and arm64 (ci.yml, job selftest).
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/trentas/ptop/internal/bpf"
	"github.com/trentas/ptop/pkg/symbol"
)

func main() {
	if spec := os.Getenv(peerEnv); spec != "" {
		runPeer(spec) // the network phase's other process; never returns
	}
	runSpec := flag.String("run", "", "comma-separated cases to run, in suite order (default: all; -list names them)")
	list := flag.Bool("list", false, "list the cases and exit")
	flag.Parse()

	cases := suite()
	if *list {
		for _, c := range cases {
			fmt.Printf("%-9s %s\n", c.name, c.what)
		}
		return
	}
	selected, err := selectCases(cases, *runSpec)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if d := bpf.GetCapStatus().Diagnose(); d != "" {
		fmt.Fprint(os.Stderr, d)
		os.Exit(1)
	}

	pid := os.Getpid()
	fmt.Printf("ptop eBPF self-test — target = self (pid %d)\n\n", pid)
	g := &grader{}
	for _, c := range selected {
		// Each case opens and closes its own tracers, so one axis's attach
		// failure cannot leave another reading a tracer it never set up.
		c.run(g, pid)
	}
	fmt.Printf("\n%s\n", g.summary())
	if g.failed > 0 {
		fmt.Fprintln(os.Stderr, "eBPF self-test FAILED")
		os.Exit(1)
	}
	fmt.Println("eBPF self-test PASSED")
}

// suite is every case, in the order they run.
func suite() []selfCase {
	return []selfCase{
		{"filter", "the pid and cgroup filters match this process (#94)", checkFilters},
		{"cpu", "on-CPU time agrees with the kernel's own accounting, quiet and busy (#108)", checkCPUAccuracy},
		{"cpusite", "CPU samples name the function that burned them (#125)", checkCPUAttribution},
		{"cpuprof", "the published profile splits a planted 60/30/10 burn within its binomial interval (#125)", checkCPUProfile},
		{"cpukernel", "the profile declares user frames only, and counts the samples that caught the CPU in the kernel (#152)", checkCPUKernel},
		{"syscalls", "a known count is named and counted exactly, a known sleep is timed (#139)", checkSyscalls},
		{"fdclass", "read and write split by the class of fd they hit, and the split adds up (#176)", checkFdClasses},
		{"futex", "waits on a known word: counted, timed, named by the waiter (#89)", checkFutex},
		{"goalloc", "two call sites at a known rate and ratio, and the census adds up (#108, #109)", checkGoAlloc},
		{"heap", "a C program's malloc, calloc and realloc sites: named, live bytes to the byte, the census adds up (#53, #109)", checkLibcHeap},
		{"gopause", "forced GC cycles stop the world twice each, timed; a non-Go target is unsupported (#175)", checkGoPauses},
		{"threads", "a sleep still going on counts in its window; a preempted thread waits in the run queue, not off-CPU (#150)", checkThreads},
		{"cost", "the heap probe's estimated cost per hit is within 2× of what an allocation costs with it attached (#154)", checkCost},
		{"budget", "--overhead-budget detaches the heap probe after three windows over it, says so, and leaves nothing spinning (#154)", checkBudget},
		{"io", "blocking reads land in their latency bucket; writes and unlinks are seen on every CPU (#159)", checkIO},
		{"restart", "a read or futex wait the kernel re-runs after a signal counts once; one that returned EINTR counts apart (#160, #164)", checkRestart},
		{"saturation", "a burner capped at 20% CPU is throttled and stalls; lifting the cap shows mid-capture (#151, #153)", checkSaturation},
		{"net", "socket ownership and bytes, against a peer in another process (#135, #142)", checkNetwork},
		{"blind", "a probe switched off says disabled, one that cannot attach says failed (#112)", checkBlind},
		{"report", "a --for window counts the calls made in it and not before, credits writes to their file, and ends when its target exits (#156)", checkReport},
	}
}

// checkFilters is the original purpose of this binary: inside containers and
// WSL, nested PID namespaces broke the target filter, and every axis read zero
// for a busy process. It burns CPU and makes write(2) calls for three seconds
// and checks that the pid filter and the cgroup filter both saw them.
func checkFilters(g *grader, pid int) {
	cpuT, err := bpf.OpenCPUTracer(bpf.TargetPID(pid))
	if err != nil {
		g.broken("filter", "pid filter, cpu", fmt.Errorf("OpenCPUTracer: %w", err))
		return
	}
	defer cpuT.Close()

	scT, err := bpf.OpenSyscallTracer(bpf.TargetPID(pid))
	if err != nil {
		g.broken("filter", "pid filter, syscalls", fmt.Errorf("OpenSyscallTracer: %w", err))
		return
	}
	defer scT.Close()

	// Second targeting mode (#94): the same workload, matched by cgroup subtree
	// instead of by pid. cgT stays nil when there is no subtree to target.
	var cgT *bpf.CPUTracer
	cgroupSpec, cgroupWhy := selfCgroup()
	if cgroupSpec != "" {
		cgT, err = bpf.OpenCPUTracer(bpf.TargetCgroup(cgroupSpec))
		if err != nil {
			g.broken("filter", "cgroup filter", fmt.Errorf("OpenCPUTracer(%s): %w", cgroupSpec, err))
		} else {
			defer cgT.Close()
			g.note("filter", "cgroup mode targeting %s", cgroupSpec)
		}
	}

	devnull, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		g.broken("filter", "workload", fmt.Errorf("open /dev/null: %w", err))
		return
	}
	defer devnull.Close()

	// Workload: CPU burn + real write(2) syscalls for 3 seconds.
	buf := []byte("x")
	var spin, writes uint64
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for i := 0; i < 50000; i++ {
			spin++
		}
		if _, err := devnull.Write(buf); err == nil {
			writes++
		}
	}
	_ = spin

	onCPU, err := cpuT.OnCPUNanos()
	g.check("filter", "pid filter, on-CPU over a 3s burn", err == nil && onCPU > 0,
		"> 0", readErr(time.Duration(onCPU).String(), err))

	stats, err := scT.Stats()
	var total uint64
	for _, s := range stats {
		total += s.Count
	}
	g.check("filter", "pid filter, syscalls", err == nil && total >= writes,
		fmt.Sprintf(">= %d (the write(2) calls made)", writes),
		readErr(fmt.Sprintf("%d across %d syscall ids", total, len(stats)), err))

	switch {
	case cgroupSpec == "":
		g.skip("filter", "cgroup filter", cgroupWhy)
	case cgT != nil:
		ns, err := cgT.OnCPUNanos()
		g.check("filter", "cgroup filter, on-CPU over a 3s burn", err == nil && ns > 0,
			"> 0", readErr(time.Duration(ns).String(), err))
	}
}

// readErr renders a reading, or the error that prevented it.
func readErr(got string, err error) string {
	if err != nil {
		return "unreadable (" + err.Error() + ")"
	}
	return got
}

// selfCgroup returns this process's cgroup v2 path, suitable as a --cgroup
// spec, or "" plus the reason there is nothing to target.
//
// Inside a cgroup namespace /proc/self/cgroup reads "0::/" — the process sees
// its own cgroup as the root — and targeting the root would mean tracing every
// process on the host, which the resolver refuses. That is a legitimate skip,
// not a failure.
func selfCgroup() (spec, why string) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", fmt.Sprintf("cannot read /proc/self/cgroup (%v)", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		// The unified hierarchy is the line with an empty controller list.
		rest, ok := strings.CutPrefix(line, "0::")
		if !ok {
			continue
		}
		if p := strings.TrimSpace(rest); p != "" && p != "/" {
			return p, ""
		}
		return "", "this process sees its own cgroup as the root (cgroup namespace) — no subtree to target"
	}
	return "", "no cgroup v2 (unified) entry in /proc/self/cgroup — cgroup v1 only host"
}

// checkCPUAccuracy is the regression test for #108: the axis has to report
// what the target actually used, not merely something greater than zero.
//
// The two points below are the pair from that report — a process at a few
// percent of a core and one at roughly ten times that. The quiet one matters
// most: it is where the old 100Hz sampler fell apart, drawing two or three
// samples a second, so that a one-second bucket was shot noise and three runs
// of one binary measured 0%, 1% and 19%. A full CPU burn is the one case that
// sampler got right, so a burn alone would not have caught any of this.
//
// Ground truth is the kernel's own sum_exec_runtime for the process, summed
// over /proc/self/task/*/schedstat. That is the nanosecond-resolution form of
// the utime+stime every `top` shows, and /proc is what a user compares ptop
// against when they doubt it.
func checkCPUAccuracy(g *grader, pid int) {
	t, err := bpf.OpenCPUTracer(bpf.TargetPID(pid))
	if err != nil {
		g.broken("cpu", "on-CPU time", fmt.Errorf("OpenCPUTracer: %w", err))
		return
	}
	defer t.Close()

	points := []struct {
		name string
		on   time.Duration // busy out of every 10ms
	}{
		{"quiet", 250 * time.Microsecond},   // ~2.5% of a core
		{"busier", 2500 * time.Microsecond}, // ~25% of a core
	}
	for _, p := range points {
		claim := fmt.Sprintf("on-CPU, %s duty cycle (%v of every 10ms)", p.name, p.on)
		got, want, err := measureCPU(t, 3*time.Second, p.on, 10*time.Millisecond)
		if err != nil {
			g.broken("cpu", claim, err)
			continue
		}
		// 15% of the truth, or 2ms, whichever is larger — the floor keeps a
		// workload this short from failing on scheduling noise alone. The
		// scheduler-timed axis lands an order of magnitude inside this; the
		// sampler it replaced did not.
		tolerance := want / 100 * 15
		if tolerance < 2*time.Millisecond {
			tolerance = 2 * time.Millisecond
		}
		diff := got - want
		if diff < 0 {
			diff = -diff
		}
		g.check("cpu", claim, diff <= tolerance,
			fmt.Sprintf("%v ±%v (/proc schedstat)", round(want), round(tolerance)),
			fmt.Sprintf("%v (off by %v)", round(got), round(diff)))
	}
}

func round(d time.Duration) time.Duration { return d.Round(time.Millisecond) }

// measureCPU runs the duty-cycled workload and returns what the axis saw and
// what /proc saw over the same interval.
func measureCPU(t *bpf.CPUTracer, total, on, period time.Duration) (axis, proc time.Duration, err error) {
	beforeBPF, err := t.OnCPUNanos()
	if err != nil {
		return 0, 0, fmt.Errorf("read on-CPU nanos: %w", err)
	}
	beforeProc, err := procOnCPUNanos()
	if err != nil {
		return 0, 0, err
	}

	burnDutyCycle(total, on, period)

	afterBPF, err := t.OnCPUNanos()
	if err != nil {
		return 0, 0, fmt.Errorf("read on-CPU nanos: %w", err)
	}
	afterProc, err := procOnCPUNanos()
	if err != nil {
		return 0, 0, err
	}
	proc = time.Duration(afterProc - beforeProc)
	if proc <= 0 {
		return 0, 0, errors.New("/proc reported no CPU time for a workload that burned some; cannot judge the axis")
	}
	return time.Duration(afterBPF - beforeBPF), proc, nil
}

// burnDutyCycle spins for `on` out of every `period` until `total` elapses,
// which puts the process at roughly on/period of one core.
func burnDutyCycle(total, on, period time.Duration) {
	deadline := time.Now().Add(total)
	var spin uint64
	for time.Now().Before(deadline) {
		until := time.Now().Add(on)
		for time.Now().Before(until) {
			for i := 0; i < 5000; i++ {
				spin++
			}
		}
		time.Sleep(period - on)
	}
	_ = spin
}

// procOnCPUNanos sums sum_exec_runtime across the process's threads. Unlike
// utime+stime in /proc/self/stat it is in nanoseconds rather than 10ms ticks,
// so it can judge a workload that only runs for a few milliseconds at a time.
func procOnCPUNanos() (uint64, error) {
	entries, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return 0, fmt.Errorf("read /proc/self/task: %w", err)
	}
	var total uint64
	for _, e := range entries {
		b, err := os.ReadFile("/proc/self/task/" + e.Name() + "/schedstat")
		if err != nil {
			continue // the thread exited between the readdir and the read
		}
		fields := strings.Fields(string(b))
		if len(fields) == 0 {
			continue
		}
		ns, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse %s schedstat: %w", e.Name(), err)
		}
		total += ns
	}
	return total, nil
}

// ─── CPU attribution (#125) ─────────────────────────────────────────────────

// cpuBurnSink keeps the burn loop from being optimized away.
var cpuBurnSink uint64

// cpuBurnHotLoop is the function the attribution axis is expected to name.
//
// Deliberately call-free arithmetic, and deliberately not inlined: the leaf
// frame of a sample taken inside it is then the function itself, so a failure
// means the axis attributed CPU to the wrong place — not that a helper got
// inlined somewhere unexpected. The deadline is checked in an outer loop so
// time.Now() is a rounding error in the sample distribution rather than a
// competing leaf.
//
//go:noinline
func cpuBurnHotLoop(d time.Duration) uint64 {
	var acc uint64
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		for i := 0; i < 20_000_000; i++ {
			acc = acc*1664525 + 1013904223
		}
	}
	return acc
}

// checkCPUAttribution is the gate for the sampled attribution axis: it burns
// CPU in a known function and fails unless the axis names THAT function.
//
// A counter that moves is not a counter that is right (#108), and for this axis
// "right" means the name. Three things are checked, because each one fails in a
// different direction:
//
//   - the burn window names cpuBurnHotLoop, with a majority of the samples;
//   - an idle window right afterwards attributes almost nothing, so the axis is
//     reporting what the target did rather than what it did once;
//   - the ACHIEVED sampling rate is reported beside the requested one, since
//     #108 measured them diverging by 10-20% on a quiet host.
func checkCPUAttribution(g *grader, pid int) {
	prof, err := bpf.OpenCPUProfiler(bpf.TargetPID(pid), bpf.CPUProfDefaultHz)
	if err != nil {
		g.broken("cpusite", "attribution", fmt.Errorf("OpenCPUProfiler: %w", err))
		return
	}
	defer prof.Close()

	sym, err := symbol.NewSymbolizer(pid)
	if err != nil {
		g.broken("cpusite", "attribution", fmt.Errorf("no symbolizer for self: %w", err))
		return
	}

	// Clear whatever the attach window collected, then measure one burn.
	if _, err := prof.Samples(); err != nil {
		g.broken("cpusite", "attribution", fmt.Errorf("Samples: %w", err))
		return
	}
	rate0, _ := prof.Rate()
	start := time.Now()
	cpuBurnSink += cpuBurnHotLoop(3 * time.Second)
	elapsed := time.Since(start)

	samples, err := prof.Samples()
	if err != nil {
		g.broken("cpusite", "attribution", fmt.Errorf("Samples: %w", err))
		return
	}
	rate1, _ := prof.Rate()

	byFunc, total, unresolved := foldSamplesByFunc(prof, sym, samples)
	if !g.check("cpusite", "samples during a 3s burn", total > 0, "> 0", fmt.Sprint(total)) {
		return
	}
	// Not a frame-pointer problem: the leaf comes from the interrupted
	// registers, so it resolves with or without them (measured — a C target
	// built both ways differed only in stack depth). A miss here means
	// bpf_get_stackid itself failed, or nothing symbolized the leaf at all.
	if !g.check("cpusite", "samples with a resolvable leaf", unresolved*2 <= total,
		"at least half", fmt.Sprintf("%d of %d", total-unresolved, total)) {
		return
	}

	top, topN := topFunc(byFunc)
	const wantFunc = "main.cpuBurnHotLoop"
	share := float64(topN) / float64(total) * 100
	g.check("cpusite", "hottest function", top == wantFunc,
		wantFunc, fmt.Sprintf("%s (%d/%d samples)", top, topN, total))
	// A correct axis puts nearly everything there; half is a floor that leaves
	// room for the runtime's own background work on a loaded machine.
	g.check("cpusite", "share of the burn in it", top == wantFunc && share >= 50,
		">= 50%", fmt.Sprintf("%.0f%% in %s", share, top))

	// The achieved rate, measured, beside the one that was asked for. Reported
	// rather than asserted: a loaded or tickless host legitimately delivers
	// fewer, and the point of publishing it is that nobody has to assume.
	if fired := rate1.Fired - rate0.Fired; fired > 0 && prof.NumCPU() > 0 {
		hz := float64(fired) / elapsed.Seconds() / float64(prof.NumCPU())
		g.note("cpusite", "sampler delivered %.0fHz per CPU of the %dHz requested", hz, prof.RequestedHz())
	}

	// Idle control: nothing is burning now, so almost nothing should be
	// attributed. An axis that keeps naming a function after the work stopped
	// is reporting its own history.
	time.Sleep(1500 * time.Millisecond)
	idle, err := prof.Samples()
	if err != nil {
		g.broken("cpusite", "samples while idle", fmt.Errorf("Samples: %w", err))
		return
	}
	_, idleTotal, _ := foldSamplesByFunc(prof, sym, idle)
	g.check("cpusite", "samples in the 1.5s idle after the burn", idleTotal <= total/10,
		fmt.Sprintf("<= %d (a tenth of the burn's)", total/10), fmt.Sprint(idleTotal))
}

// foldSamplesByFunc resolves each stack's LEAF frame — the function actually
// executing when the sample was taken — and sums the samples per function name.
// This is a self-time profile: there is no walking past machinery here, the way
// the heap axis walks past the allocator, because on this axis the machinery IS
// where the time went.
func foldSamplesByFunc(prof *bpf.CPUProfiler, sym *symbol.Symbolizer, samples map[int32]bpf.CPUProfCount) (byFunc map[string]uint64, total, unresolved uint64) {
	byFunc = make(map[string]uint64, len(samples))
	for sid, c := range samples {
		n := c.Samples
		total += n
		frames, err := prof.ResolveStack(sid)
		if err != nil || len(frames) == 0 {
			unresolved += n
			continue
		}
		name := sym.Symbolize(frames[0]).Func
		if name == "" {
			unresolved += n
			continue
		}
		byFunc[name] += n
	}
	return byFunc, total, unresolved
}

// topFunc returns the most-sampled function, ties broken by name so a failure
// message is reproducible.
func topFunc(byFunc map[string]uint64) (string, uint64) {
	names := make([]string, 0, len(byFunc))
	for name := range byFunc {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if byFunc[names[i]] != byFunc[names[j]] {
			return byFunc[names[i]] > byFunc[names[j]]
		}
		return names[i] < names[j]
	})
	if len(names) == 0 {
		return "", 0
	}
	return names[0], byFunc[names[0]]
}
