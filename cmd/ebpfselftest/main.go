//go:build linux && ebpf

// ebpf-selftest verifies that ptop's eBPF collectors can actually observe
// the target process — useful inside containers / WSL, where nested PID
// namespaces historically broke the filter. Run as root:
//
//	sudo ./bin/ebpf-selftest
//
// It targets its own process, generates a known workload (CPU burn + write
// syscalls), and reports whether the eBPF counters moved. Exit code is 0 on
// PASS, 1 on FAIL — usable directly in CI / scripts.
package main

import (
	"errors"
	"fmt"
	"os"
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

	samples, _ := cpuT.SampleCount()
	if samples > 0 {
		fmt.Printf("PASS  cpu:      %d on-CPU samples observed\n", samples)
	} else {
		fmt.Fprintln(os.Stderr, "FAIL  cpu:      0 samples — the eBPF filter did not match this process")
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
		if samples, _ := cgT.SampleCount(); samples > 0 {
			fmt.Printf("PASS  cgroup:   %d on-CPU samples observed via cgroup subtree filter\n", samples)
		} else {
			fmt.Fprintln(os.Stderr, "FAIL  cgroup:   0 samples — the cgroup subtree filter did not match this process")
			failed = true
		}
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
