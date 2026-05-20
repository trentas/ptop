//go:build linux && ebpf

// ebpf-selftest verifies that ptop's eBPF collectors can actually observe
// the target process — useful inside containers / WSL, where nested PID
// namespaces historically broke the filter. Run as root:
//
//	sudo ./bin/ebpf-selftest
//
// It targets its own process, generates a known workload (CPU burn + write
// syscalls), and reports whether the eBPF counters moved.
package main

import (
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

	pid := os.Getpid()
	fmt.Printf("ptop eBPF self-test — target = self (pid %d)\n\n", pid)

	cpuT, err := bpf.OpenCPUTracer(pid)
	if err != nil {
		fmt.Println("FAIL  cpu: OpenCPUTracer:", err)
		os.Exit(1)
	}
	defer cpuT.Close()

	scT, err := bpf.OpenSyscallTracer(pid)
	if err != nil {
		fmt.Println("FAIL  syscalls: OpenSyscallTracer:", err)
		os.Exit(1)
	}
	defer scT.Close()

	// Workload: CPU burn + real write(2) syscalls for 3 seconds.
	devnull, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		fmt.Println("FAIL  cannot open /dev/null:", err)
		os.Exit(1)
	}
	buf := []byte("x")
	var spin uint64
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for i := 0; i < 50000; i++ {
			spin++
		}
		_, _ = devnull.Write(buf)
	}
	devnull.Close()
	_ = spin

	failed := false

	samples, _ := cpuT.SampleCount()
	if samples > 0 {
		fmt.Printf("PASS  cpu:      %d on-CPU samples observed\n", samples)
	} else {
		fmt.Println("FAIL  cpu:      0 samples — the eBPF filter did not match this process")
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
		fmt.Println("FAIL  syscalls: 0 events — the eBPF filter did not match this process")
		failed = true
	}

	if failed {
		fmt.Println("\neBPF self-test FAILED")
		os.Exit(1)
	}
	fmt.Println("\neBPF self-test PASSED")
}
