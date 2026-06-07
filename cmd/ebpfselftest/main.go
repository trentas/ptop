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

	cpuT, err := bpf.OpenCPUTracer(pid)
	if err != nil {
		return fmt.Errorf("cpu: OpenCPUTracer: %w", err)
	}
	defer cpuT.Close()

	scT, err := bpf.OpenSyscallTracer(pid)
	if err != nil {
		return fmt.Errorf("syscalls: OpenSyscallTracer: %w", err)
	}
	defer scT.Close()

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

	if failed {
		return errors.New("eBPF self-test FAILED")
	}
	fmt.Println("\neBPF self-test PASSED")
	return nil
}
