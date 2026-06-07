//go:build linux

package collector

import "testing"

// TestDetectClkTck — on any POSIX system `getconf CLK_TCK` returns a
// sensible value. On systems where the command doesn't exist, the fallback
// is 100. We verify it returns >0 and is in a reasonable range.
func TestDetectClkTck(t *testing.T) {
	v := detectClkTck()
	if v <= 0 {
		t.Fatalf("clkTck must be positive, got %v", v)
	}
	// Known values: 100 (x86 Ubuntu), 250 (ARM Ubuntu/RHEL), 1000 (Fedora ARM)
	if v < 50 || v > 10000 {
		t.Errorf("clkTck %v outside reasonable range (50..10000)", v)
	}
}
