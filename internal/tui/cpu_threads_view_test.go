package tui

import (
	"strings"
	"testing"

	"github.com/trentas/ptop/pkg/collector"
)

func TestCPUScaleIsWholeCores(t *testing.T) {
	cases := []struct {
		name    string
		history []float64
		n       int
		want    float64
	}{
		{"no samples", nil, 0, 100},
		{"under a core", []float64{3, 40, 99.5}, 0, 100},
		{"exactly one core", []float64{100}, 0, 100},
		{"a little over one core", []float64{20, 101}, 0, 200},
		{"four busy cores", []float64{390, 400}, 0, 400},
		{"an old peak outside the drawn window", []float64{350, 50, 60}, 2, 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cpuScale(tc.history, tc.n); got != tc.want {
				t.Fatalf("cpuScale = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCPUSparklineDoesNotFlattenSeveralCores: the value is top-style, so a
// process on 2.5 cores reads 250%. Against the mockup's fixed 100% ceiling
// every sample drew a full cell, and 250% looked like 100%.
func TestCPUSparklineDoesNotFlattenSeveralCores(t *testing.T) {
	history := make([]float64, 60)
	for i := range history {
		history[i] = 250
	}
	out := ansiRe.ReplaceAllString(renderCPU(history, cpuSiteSummary{}, true, 60, 2), "")
	if !strings.Contains(out, "cpu · 0–300%") {
		t.Errorf("label does not name the 300%% ceiling:\n%s", out)
	}
	if strings.Contains(out, "⣿") {
		t.Errorf("250%% of a 300%% ceiling drew full cells:\n%s", out)
	}

	for i := range history {
		history[i] = 40
	}
	if out := ansiRe.ReplaceAllString(renderCPU(history, cpuSiteSummary{}, true, 60, 2), ""); !strings.Contains(out, "cpu usage") {
		t.Errorf("under one core the label stays \"cpu usage\":\n%s", out)
	}
}

// TestThreadRowsShowTheWindowNotTheSample: CPU% covers the window, the state
// is one sample at read time. A thread at 60% that was asleep when read drew
// an empty bar, and a measured 0% printed "--".
func TestThreadRowsShowTheWindowNotTheSample(t *testing.T) {
	threads := []collector.ThreadInfo{
		{TID: 1, Name: "worker", State: "sleeping", CPUPct: 60},
		{TID: 2, Name: "idle", State: "sleeping"},
	}
	rows := strings.Split(ansiRe.ReplaceAllString(renderThreadTable(threads, true, 100, 10), ""), "\n")
	if len(rows) < 3 {
		t.Fatalf("table too short:\n%s", strings.Join(rows, "\n"))
	}
	worker, idle := rows[1], rows[2]
	if !strings.Contains(worker, "█") || !strings.Contains(worker, "60%") {
		t.Errorf("a sleeping thread at 60%% must draw its bar: %q", worker)
	}
	if strings.Contains(idle, "--") || !strings.Contains(idle, "0%") {
		t.Errorf("a measured 0%% reads 0%%: %q", idle)
	}

	// The /proc lane does not split off-CPU time: OFF% and RUNQ% are not
	// readings there.
	procRows := strings.Split(ansiRe.ReplaceAllString(renderThreadTable(threads, false, 100, 10), ""), "\n")
	if got := strings.Count(procRows[2], "—"); got < 2 {
		t.Errorf("OFF%% and RUNQ%% unmeasured must read —: %q", procRows[2])
	}
	if strings.Count(rows[2], "—") != 0 {
		t.Errorf("on the eBPF lane OFF%% and RUNQ%% are readings: %q", rows[2])
	}

	list := ansiRe.ReplaceAllString(renderThreadList(threads, 60, 5), "")
	if !strings.Contains(strings.Split(list, "\n")[0], "█") {
		t.Errorf("F1's thread list must draw the sleeping worker's bar too:\n%s", list)
	}
}
