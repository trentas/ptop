package collector

import (
	"math"
	"testing"
	"time"
)

func TestCPUPercent(t *testing.T) {
	const sec = uint64(time.Second)

	tests := []struct {
		name      string
		prev, cur uint64
		elapsed   time.Duration
		ncpu      int
		want      float64
	}{
		{"idle", 100, 100, time.Second, 8, 0},
		{"one core flat out", 0, sec, time.Second, 8, 100},
		{"a quiet 2.5% — the case the sampler could not resolve", 0, sec / 40, time.Second, 8, 2.5},
		{"four threads on four cores", 0, 4 * sec, time.Second, 8, 400},
		{"half a second of wall clock", 0, sec / 4, 500 * time.Millisecond, 8, 50},
		{"saturates at the core count", 0, 100 * sec, time.Second, 8, 800},
		{"counter went backwards", 500, 400, time.Second, 8, 0},
		{"no interval", 0, sec, 0, 8, 0},
		{"unknown core count does not clamp", 0, 100 * sec, time.Second, 0, 10000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cpuPercent(tc.prev, tc.cur, tc.elapsed, tc.ncpu)
			if math.Abs(got-tc.want) > 1e-9 {
				t.Errorf("cpuPercent(%d, %d, %v, %d) = %v, want %v",
					tc.prev, tc.cur, tc.elapsed, tc.ncpu, got, tc.want)
			}
		})
	}
}
