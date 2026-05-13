//go:build darwin

package collector

import (
	"os"
	"testing"
	"time"
)

// TestCPUCollector_self verifies the darwin CPU collector publishes samples
// against its own pid and that a CPU-bound goroutine pushes the value above
// zero. This is an integration smoke test for proc_pidinfo + delta logic.
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
			// At least one sample after the first delta should be non-zero,
			// because we have a CPU-burning goroutine.
			var saw bool
			for _, s := range samples[1:] {
				if s.UsagePct > 1.0 { // > 1% — very conservative threshold
					saw = true
					break
				}
			}
			if !saw {
				t.Fatalf("CPU-bound goroutine running but all samples were <1%%: %+v", samples)
			}
			t.Logf("collected %d samples: %+v", len(samples), samples)
			return
		case msg := <-cpu.Subscribe():
			samples = append(samples, msg.(CpuSample))
		}
	}
}
