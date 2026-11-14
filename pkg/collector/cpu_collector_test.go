//go:build linux || darwin

package collector

import (
	"os"
	"testing"
	"time"
)

// TestCPUCollector_self verifies the non-eBPF CPU collector (libproc on darwin,
// /proc on linux) publishes samples against its own pid and that a CPU-bound
// goroutine pushes every one of them above zero, the first included: a first
// sample taken with no baseline is a structural zero (#156).
func TestCPUCollector_self(t *testing.T) {
	cpu := NewCPUCollector()
	if err := cpu.Start(os.Getpid()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer cpu.Stop()

	// Burn CPU in the background so we observe non-trivial utilization.
	burnStop := make(chan struct{})
	go func() {
		x := 1
		for {
			select {
			case <-burnStop:
				return
			default:
				x = (x*7 + 3) % 997
				_ = x
			}
		}
	}()
	defer close(burnStop)

	deadline := time.After(3 * time.Second)
	var samples []CpuSample
	for {
		select {
		case <-deadline:
			if len(samples) == 0 {
				t.Fatalf("got no samples after 3s")
			}
			// A goroutine burns CPU the whole time, so no sample may read
			// idle. 1% is a very conservative threshold.
			for i, s := range samples {
				if s.UsagePct < 1.0 {
					t.Fatalf("CPU-bound goroutine running but sample %d read %.2f%%: %+v", i, s.UsagePct, samples)
				}
			}
			t.Logf("collected %d samples: %+v", len(samples), samples)
			return
		case msg := <-cpu.Subscribe():
			samples = append(samples, msg.(CpuSample))
		}
	}
}
