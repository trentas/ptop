//go:build linux && ebpf

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trentas/ptop/internal/bpf"
	"github.com/trentas/ptop/internal/report"
	"github.com/trentas/ptop/internal/serve"
	"github.com/trentas/ptop/pkg/collector"
	pb "github.com/trentas/ptop/pkg/streampb"
)

// ─── unmatched: a filter that matches nothing fails its probes (#199) ──────
//
// #193 and #197 were the same failure twice: the target filter loaded, matched
// nothing, and every probe behind it reported `active` while every axis read
// zero. This case builds that filter on purpose (bpf.MisdirectFiltersForSelftest)
// and grades what ptop says about it:
//
//   - pid mode, a busy target: the filter compares with a pid no task can have
//     (past pid_max's ceiling, so it cannot land on another process). Every
//     probe behind it must fail within a few seconds, with a detail giving
//     both numbers; io keeps its /proc lane; signals and lifecycle, behind a
//     filter of their own, stay active; nothing the failed probes publish
//     reaches a consumer after the change; and a --for report over the same
//     capture has no cpu or syscalls section, only the failure.
//   - pid mode, an idle target under the same misdirected filter: no switches,
//     no evidence, and nothing may fail, however long the capture.
//   - pid mode, the busy target under its real filter: nothing may fail.
//   - cgroup mode: the filter names an empty decoy cgroup instead of the
//     target's. Every probe fails, naming the cgroup the evidence came from;
//     under the real cgroup nothing fails.
//
// The busy target is a child that naps 2ms at a time, a getppid each, so
// hundreds of switches a second; the idle one is sleep(1), blocked in one
// clock_nanosleep for the whole case.

// unmatchedPIDOffset moves a pid filter past the highest pid Linux can hand out
// (pid_max is at most 2^22), so it matches no task at all.
const unmatchedPIDOffset = 1 << 22

// unmatchedWindow is how long each capture is watched. The check reads once a
// second and needs 20 switches; the napper makes that in its first tens of
// milliseconds.
const unmatchedWindow = 5 * time.Second

// probeWatch records what one Set's bus delivers: the probe changes, and any
// value from a probe behind the filter that arrives once they settled.
type probeWatch struct {
	mu       sync.Mutex
	began    time.Time
	changes  []collector.ProbeChange
	changeAt time.Time
	late     map[string]int
	getppid  uint64
}

func watchFeed(f *collector.Feed) (*probeWatch, func()) {
	w := &probeWatch{began: time.Now(), late: map[string]int{}}
	h := f.Bus.AddHandler(func(v any) {
		w.mu.Lock()
		defer w.mu.Unlock()
		switch x := v.(type) {
		case collector.ProbeChange:
			w.changes = append(w.changes, x)
			w.changeAt = time.Now()
			return
		case []collector.SyscallEvent:
			for _, s := range x {
				if s.Name == "getppid" {
					w.getppid = s.Count
				}
			}
		}
		// A value sent just before the flag was set can still be broadcast
		// just after the change: a quarter of a second covers that.
		if behindFilter(v) && len(w.changes) > 0 && time.Since(w.changeAt) > 250*time.Millisecond {
			w.late[fmt.Sprintf("%T", v)]++
		}
	})
	return w, func() { f.Bus.RemoveHandler(h) }
}

// behindFilter reports whether a value comes from a probe behind the shared
// filter, in a Set where that probe runs on eBPF.
func behindFilter(v any) bool {
	switch v.(type) {
	case collector.CpuSample, []collector.SyscallEvent, []collector.ThreadInfo, collector.MemStats,
		collector.HeapStats, collector.CPUProfile, collector.GoPauses, collector.RunqLatency,
		collector.IOEBPFSnapshot, []collector.NetConn, collector.NetThroughputSample, []collector.LockEntry:
		return true
	}
	return false
}

// activeBehindFilter is what failFilter must fail: every probe behind the
// filter that runs on eBPF.
func activeBehindFilter(probes []collector.ProbeStatus) []string {
	behind := map[string]bool{}
	for _, n := range collector.FilterSubsystems() {
		behind[n] = true
	}
	var out []string
	for _, st := range probes {
		if behind[st.Name] && st.State == collector.ProbeActive && st.Source == "eBPF" {
			out = append(out, st.Name)
		}
	}
	sort.Strings(out)
	return out
}

func probeState(probes []collector.ProbeStatus, name string) collector.ProbeStatus {
	for _, st := range probes {
		if st.Name == name {
			return st
		}
	}
	return collector.ProbeStatus{Name: name, State: "absent"}
}

func ctxSwitches(pid int) uint64 {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	var n uint64
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.HasSuffix(k, "ctxt_switches") {
			x, _ := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			n += x
		}
	}
	return n
}

func checkUnmatched(g *grader, _ int) {
	checkUnmatchedPID(g)
	checkUnmatchedCgroup(g)
}

func checkUnmatchedPID(g *grader) {
	const axis = "unmatched"
	napper := peerCmd("napper")
	if err := napper.Start(); err != nil {
		g.broken(axis, "start the busy target", err)
		return
	}
	defer func() { _ = napper.Process.Kill(); _ = napper.Wait() }()
	busy := napper.Process.Pid

	var sleeper *exec.Cmd
	if path, err := exec.LookPath("sleep"); err == nil {
		sleeper = exec.Command(path, "600")
		if err := sleeper.Start(); err != nil {
			g.broken(axis, "start the idle target", err)
			return
		}
		defer func() { _ = sleeper.Process.Kill(); _ = sleeper.Wait() }()
	}
	time.Sleep(200 * time.Millisecond) // both past their start-up

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The control first, while filters still follow their target.
	okFeed := collector.StartFeed(ctx, collector.SetConfig{PID: busy,
		Disable: onlySubsystems(collector.SubsystemCPU, collector.SubsystemSyscalls, collector.SubsystemThreads)})
	defer okFeed.Stop()
	okWatch, unwatch := watchFeed(okFeed)
	defer unwatch()

	restore := bpf.MisdirectFiltersForSelftest(bpf.Misdirection{PIDOffset: unmatchedPIDOffset})
	var idleFeed *collector.Feed
	var idleWatch *probeWatch
	var idleSwitches uint64
	if sleeper != nil {
		idleSwitches = ctxSwitches(sleeper.Process.Pid)
		idleFeed = collector.StartFeed(ctx, collector.SetConfig{PID: sleeper.Process.Pid})
		defer idleFeed.Stop()
		var unwatchIdle func()
		idleWatch, unwatchIdle = watchFeed(idleFeed)
		defer unwatchIdle()
	}
	blindFeed := collector.StartFeed(ctx, collector.SetConfig{PID: busy, ListCap: report.CollectorListCap})
	restore()
	defer blindFeed.Stop()
	blindWatch, unwatchBlind := watchFeed(blindFeed)
	defer unwatchBlind()
	initial := blindFeed.Set.Probes()
	want := activeBehindFilter(initial)

	// The same capture, as an agent reads it.
	res := make(chan captureResult, 1)
	go func() {
		r, err := serve.Capture(ctx, serve.TargetPID(busy), blindFeed, nil, serve.CaptureOptions{
			For: unmatchedWindow, TopN: report.DefaultTopN, ListCap: report.CollectorListCap,
		})
		res <- captureResult{r, err}
	}()
	var x captureResult
	select {
	case x = <-res:
	case <-time.After(unmatchedWindow + 10*time.Second):
		g.broken(axis, "the --for window over the misdirected capture", errors.New("Capture did not return"))
		return
	}
	if x.err != nil {
		g.broken(axis, "the --for window over the misdirected capture", x.err)
		return
	}

	// ── The busy target, misdirected ──
	blindWatch.mu.Lock()
	changes := append([]collector.ProbeChange(nil), blindWatch.changes...)
	took := blindWatch.changeAt.Sub(blindWatch.began)
	late := fmt.Sprint(blindWatch.late)
	nLate := len(blindWatch.late)
	blindWatch.mu.Unlock()

	failed := map[string]collector.ProbeStatus{}
	for _, c := range changes {
		failed[c.Status.Name] = c.Status
	}
	var gotNames []string
	for n := range failed {
		gotNames = append(gotNames, n)
	}
	sort.Strings(gotNames)
	if !g.check(axis, "pid filter matching nothing: every eBPF probe behind it changes state",
		strings.Join(gotNames, ",") == strings.Join(want, ","), strings.Join(want, ","), strings.Join(gotNames, ",")) {
		return
	}
	g.check(axis, "the verdict comes within 3s of the attach", took <= 3*time.Second, "≤ 3s", took.Round(time.Millisecond).String())

	wantIO := collector.ProbeStatus{Name: collector.SubsystemIO, State: collector.ProbeFailed}
	if blindFeed.Set.IOWait != nil || blindFeed.Set.IOThroughput != nil {
		wantIO = collector.ProbeStatus{Name: collector.SubsystemIO, State: collector.ProbeActive, Source: collector.SourceProc}
	}
	var wrong []string
	for _, n := range want {
		st := failed[n]
		ok := st.State == collector.ProbeFailed
		if n == collector.SubsystemIO {
			ok = st.State == wantIO.State && st.Source == wantIO.Source
		}
		if !ok || !strings.Contains(st.Detail, collector.FilterBlindPrefix) {
			wrong = append(wrong, fmt.Sprintf("%s %s/%s", n, st.State, st.Source))
		}
	}
	g.check(axis, "each is failed (io: on /proc), and says the filter matches nothing",
		len(wrong) == 0, "none wrong", fmt.Sprint(wrong))

	d := failed[collector.SubsystemCPU].Detail
	switches := -1
	if i := strings.Index(d, "counted "); i >= 0 {
		_, _ = fmt.Sscanf(d[i:], "counted %d context switches", &switches)
	}
	g.check(axis, "the detail gives both numbers: /proc's switches and the filter's 0",
		switches >= 20 && strings.Contains(d, "matched 0 of them"), "≥ 20 switches, matched 0", d)

	after := blindFeed.Set.Probes()
	sig, life := probeState(after, collector.SubsystemSignals), probeState(after, collector.SubsystemLifecycle)
	g.check(axis, "signals and lifecycle, behind a filter of their own, stay active",
		sig.State == collector.ProbeActive && life.State == collector.ProbeActive,
		"active, active", fmt.Sprintf("%s, %s", sig.State, life.State))
	g.check(axis, "the probe set a later handshake reads says failed",
		probeState(after, collector.SubsystemCPU).State == collector.ProbeFailed,
		"cpu failed", string(probeState(after, collector.SubsystemCPU).State))
	g.check(axis, "nothing a failed probe publishes reaches a consumer after the change",
		nLate == 0, "nothing", late)

	r := x.r
	cpuFailed := false
	for _, c := range r.GetProbeChanges() {
		if c.GetProbe().GetName() == collector.SubsystemCPU && c.GetProbe().GetState() == pb.ProbeState_PROBE_STATE_FAILED {
			cpuFailed = true
		}
	}
	for _, p := range r.GetTarget().GetProbes() {
		if p.GetName() == collector.SubsystemCPU && p.GetState() == pb.ProbeState_PROBE_STATE_FAILED {
			cpuFailed = true // the verdict came before the window opened
		}
	}
	g.check(axis, "the --for report says the cpu probe failed", cpuFailed, "failed, in probe_changes or the probe set",
		fmt.Sprintf("%d changes", len(r.GetProbeChanges())))
	g.check(axis, "… and has no cpu, syscalls or threads section: those zeros were the filter",
		r.GetCpu() == nil && r.GetSyscalls() == nil && r.GetThreads() == nil, "absent",
		fmt.Sprintf("cpu %v, syscalls %v, threads %v", r.GetCpu() != nil, r.GetSyscalls() != nil, r.GetThreads() != nil))
	g.check(axis, "… while signals, still measured, keep theirs", r.GetSignals() != nil, "present", fmt.Sprint(r.GetSignals() != nil))

	// ── The idle target, misdirected the same way ──
	if idleFeed == nil {
		g.skip(axis, "an idle target under a filter that matches nothing stays active", "no sleep(1) on this host")
	} else {
		idleWatch.mu.Lock()
		n := len(idleWatch.changes)
		idleWatch.mu.Unlock()
		made := ctxSwitches(sleeper.Process.Pid) - idleSwitches
		g.note(axis, "the idle target made %d context switches while watched", made)
		g.check(axis, fmt.Sprintf("an idle target under a filter that matches nothing: nothing fails in %v", time.Since(idleWatch.began).Round(time.Second)),
			n == 0, "no change", fmt.Sprintf("%d changes", n))
		st := probeState(idleFeed.Set.Probes(), collector.SubsystemCPU)
		g.check(axis, "… and its probes still say active", st.State == collector.ProbeActive, "active", string(st.State))
	}

	// ── The busy target under its real filter ──
	okWatch.mu.Lock()
	n, calls := len(okWatch.changes), okWatch.getppid
	okWatch.mu.Unlock()
	g.check(axis, "the busy target under its real filter: nothing fails", n == 0, "no change", fmt.Sprintf("%d changes", n))
	g.check(axis, "… and its getppid calls are counted", calls > 100, "> 100", strconv.FormatUint(calls, 10))
}

func checkUnmatchedCgroup(g *grader) {
	const axis = "unmatched"
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		g.skip(axis, "cgroup filter matching nothing", "no cgroup v2 hierarchy mounted at /sys/fs/cgroup")
		return
	}
	target := fmt.Sprintf("/sys/fs/cgroup/ptop-selftest-unmatched-%d", os.Getpid())
	decoy := fmt.Sprintf("/sys/fs/cgroup/ptop-selftest-decoy-%d", os.Getpid())
	for _, d := range []string{target, decoy} {
		if err := os.Mkdir(d, 0o755); err != nil {
			g.broken(axis, "create the cgroups", err)
			return
		}
	}
	defer removeCgroups(target, decoy)
	napper := peerCmd("napper")
	if err := napper.Start(); err != nil {
		g.broken(axis, "start the busy target", err)
		return
	}
	defer func() { _ = napper.Process.Kill(); _ = napper.Wait() }() // before the rmdir
	if err := os.WriteFile(filepath.Join(target, "cgroup.procs"), []byte(strconv.Itoa(napper.Process.Pid)), 0); err != nil {
		g.broken(axis, "move the busy target into its cgroup", err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	okFeed := collector.StartFeed(ctx, collector.SetConfig{Cgroup: target,
		Disable: onlySubsystems(collector.SubsystemCPU, collector.SubsystemSyscalls)})
	defer okFeed.Stop()
	okWatch, unwatch := watchFeed(okFeed)
	defer unwatch()

	restore := bpf.MisdirectFiltersForSelftest(bpf.Misdirection{DecoyCgroup: decoy})
	blindFeed := collector.StartFeed(ctx, collector.SetConfig{Cgroup: target})
	restore()
	defer blindFeed.Stop()
	blindWatch, unwatchBlind := watchFeed(blindFeed)
	defer unwatchBlind()
	want := activeBehindFilter(blindFeed.Set.Probes())

	time.Sleep(unmatchedWindow)

	blindWatch.mu.Lock()
	changes := append([]collector.ProbeChange(nil), blindWatch.changes...)
	blindWatch.mu.Unlock()
	failed := map[string]collector.ProbeStatus{}
	var names []string
	for _, c := range changes {
		if c.Status.State == collector.ProbeFailed {
			failed[c.Status.Name] = c.Status
			names = append(names, c.Status.Name)
		}
	}
	sort.Strings(names)
	g.check(axis, "cgroup filter naming a decoy: every eBPF probe behind it fails (no /proc lane here)",
		strings.Join(names, ",") == strings.Join(want, ","), strings.Join(want, ","), strings.Join(names, ","))
	d := failed[collector.SubsystemCPU].Detail
	g.check(axis, "… and the detail names the cgroup the switches were counted in",
		strings.HasPrefix(d, collector.FilterBlindPrefix) && strings.Contains(d, "the threads of cgroup "+target),
		"… of the threads of cgroup "+target, d)

	okWatch.mu.Lock()
	n, calls := len(okWatch.changes), okWatch.getppid
	okWatch.mu.Unlock()
	g.check(axis, "the busy target under its real cgroup filter: nothing fails", n == 0, "no change", fmt.Sprintf("%d changes", n))
	g.check(axis, "… and its getppid calls are counted", calls > 100, "> 100", strconv.FormatUint(calls, 10))
}
