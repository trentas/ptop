package bpf

import (
	"strings"
	"testing"
)

func TestNormalizeCPUProfHz(t *testing.T) {
	tests := []struct {
		name     string
		in       int
		want     int
		warnHas  string
		wantWarn bool
	}{
		// The zero value of a config struct has to be the cheap, safe rate:
		// nothing downstream should have to remember to fill this in.
		{name: "unset takes the default", in: 0, want: CPUProfDefaultHz},
		{name: "a plain rate passes through", in: 50, want: 50},
		{name: "the default itself is quiet", in: CPUProfDefaultHz, want: CPUProfDefaultHz},
		{
			name: "a high rate is used and named out loud",
			in:   400, want: 400, wantWarn: true, warnHas: "every CPU",
		},
		{
			name: "past the cap it is clamped, and says so",
			in:   50000, want: CPUProfMaxHz, wantWarn: true, warnHas: "cap",
		},
		{
			name: "a negative rate is not a rate",
			in:   -5, want: CPUProfDefaultHz, wantWarn: true, warnHas: "not a rate",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, warn := NormalizeCPUProfHz(tt.in)
			if got != tt.want {
				t.Errorf("NormalizeCPUProfHz(%d) = %d, want %d", tt.in, got, tt.want)
			}
			if (warn != "") != tt.wantWarn {
				t.Errorf("warning = %q, want warning: %v", warn, tt.wantWarn)
			}
			if tt.warnHas != "" && !strings.Contains(warn, tt.warnHas) {
				t.Errorf("warning %q should mention %q", warn, tt.warnHas)
			}
		})
	}
}

// 99 rather than 100 is a deliberate choice, pinned so it is not "tidied" to a
// round number. It is insurance against phase-locking on a periodic workload,
// not a fix for a defect measured here — 100Hz against an 8ms/2ms duty cycle
// did NOT lock on a 7.0 kernel (freq mode dithers the period). See
// CPUProfDefaultHz for the measurement and why the choice stands anyway.
func TestCPUProfDefaultRateDoesNotDivideCommonPeriods(t *testing.T) {
	// Periods a real workload ticks at, in Hz.
	for _, common := range []int{1, 2, 4, 5, 10, 20, 25, 50, 100, 250, 1000} {
		if CPUProfDefaultHz%common == 0 && common != 1 {
			t.Errorf("default %dHz is a multiple of %dHz: it samples one phase of that cycle forever",
				CPUProfDefaultHz, common)
		}
		if common%CPUProfDefaultHz == 0 {
			t.Errorf("%dHz is a multiple of the default %dHz: same aliasing, other direction",
				common, CPUProfDefaultHz)
		}
	}
}
