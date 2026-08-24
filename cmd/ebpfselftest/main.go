//go:build linux && ebpf

// ebpf-selftest verifies that ptop's eBPF collectors can actually observe
// the target process — useful inside containers / WSL, where nested PID
// namespaces historically broke the filter. Run as root:
//
//	sudo ./bin/ebpf-selftest
//
// It targets its own process, generates a known workload (CPU burn + write
// syscalls), and reports whether the eBPF counters moved. It then runs a
// second, deliberately quiet workload and checks that the CPU axis agrees
// with the kernel's own accounting of it — a counter that moves is not the
// same as a counter that is right (#108). Exit code is 0 on PASS, 1 on FAIL —
// usable directly in CI / scripts.
package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/trentas/ptop/internal/bpf"
)

func main() {
	if d := bpf.GetCapStatus().Diagnose(); d != "" {
		fmt.Fprint(os.Stderr, d)
		os.Exit(1)
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run performs the self-test. Returning an error (instead of calling
// os.Exit directly) ensures the deferred tracer Close() calls always run.
func run() error {
	pid := os.Getpid()
	fmt.Printf("ptop eBPF self-test — target = self (pid %d)\n\n", pid)

	cpuT, err := bpf.OpenCPUTracer(bpf.TargetPID(pid))
	if err != nil {
		return fmt.Errorf("cpu: OpenCPUTracer: %w", err)
	}
	defer cpuT.Close()

	scT, err := bpf.OpenSyscallTracer(bpf.TargetPID(pid))
	if err != nil {
		return fmt.Errorf("syscalls: OpenSyscallTracer: %w", err)
	}
	defer scT.Close()

	// Second targeting mode (#94): the same workload, matched by cgroup subtree
	// instead of by pid. cgT stays nil when there is no subtree to target.
	var cgT *bpf.CPUTracer
	cgroupSpec, cgroupWhy := selfCgroup()
	if cgroupSpec != "" {
		cgT, err = bpf.OpenCPUTracer(bpf.TargetCgroup(cgroupSpec))
		if err != nil {
			return fmt.Errorf("cgroup: OpenCPUTracer(%s): %w", cgroupSpec, err)
		}
		defer cgT.Close()
		fmt.Printf("      cgroup mode targeting %s\n\n", cgroupSpec)
	}

	devnull, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open /dev/null: %w", err)
	}
	defer devnull.Close()

	// Workload: CPU burn + real write(2) syscalls for 3 seconds.
	buf := []byte("x")
	var spin uint64
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for i := 0; i < 50000; i++ {
			spin++
		}
		_, _ = devnull.Write(buf)
	}
	_ = spin

	failed := false

	onCPU, _ := cpuT.OnCPUNanos()
	if onCPU > 0 {
		fmt.Printf("PASS  cpu:      %v of on-CPU time observed\n", time.Duration(onCPU))
	} else {
		fmt.Fprintln(os.Stderr, "FAIL  cpu:      0ns on-CPU — the eBPF filter did not match this process")
		failed = true
	}

	stats, _ := scT.Stats()
	var total uint64
	for _, s := range stats {
		total += s.Count
	}
	if total > 0 {
		fmt.Printf("PASS  syscalls: %d events across %d syscall ids\n", total, len(stats))
	} else {
		fmt.Fprintln(os.Stderr, "FAIL  syscalls: 0 events — the eBPF filter did not match this process")
		failed = true
	}

	switch {
	case cgT == nil:
		fmt.Printf("SKIP  cgroup:   %s\n", cgroupWhy)
	default:
		if ns, _ := cgT.OnCPUNanos(); ns > 0 {
			fmt.Printf("PASS  cgroup:   %v of on-CPU time observed via cgroup subtree filter\n", time.Duration(ns))
		} else {
			fmt.Fprintln(os.Stderr, "FAIL  cgroup:   0ns on-CPU — the cgroup subtree filter did not match this process")
			failed = true
		}
	}

	if !checkCPUAccuracy(cpuT) {
		failed = true
	}

	if failed {
		return errors.New("eBPF self-test FAILED")
	}
	fmt.Println("\neBPF self-test PASSED")
	return nil
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
func checkCPUAccuracy(t *bpf.CPUTracer) bool {
	points := []struct {
		name string
		on   time.Duration // busy out of every 10ms
	}{
		{"quiet", 250 * time.Microsecond},   // ~2.5% of a core
		{"busier", 2500 * time.Microsecond}, // ~25% of a core
	}
	ok := true
	for _, p := range points {
		got, want, err := measureCPU(t, 3*time.Second, p.on, 10*time.Millisecond)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL  cpu%% %-7s %v\n", p.name+":", err)
			ok = false
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
		if diff > tolerance {
			fmt.Fprintf(os.Stderr, "FAIL  cpu%% %-7s axis says %v, /proc says %v — off by %v, more than the %v allowed\n",
				p.name+":", round(got), round(want), round(diff), round(tolerance))
			ok = false
			continue
		}
		fmt.Printf("PASS  cpu%% %-7s %v on-CPU vs %v in /proc (±%v)\n",
			p.name+":", round(got), round(want), round(tolerance))
	}
	return ok
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
