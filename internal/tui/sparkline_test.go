package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

// plainSpark strips styling so the runes can be inspected.
func plainSpark(data []float64, width int, max float64) []rune {
	out := SparklineWithMax(data, width, max, ColorGreen)
	var runes []rune
	in := false
	for _, r := range out {
		switch {
		case r == 0x1b:
			in = true
		case in && r == 'm':
			in = false
		case !in:
			runes = append(runes, r)
		}
	}
	return runes
}

// The defect this replaced: height stopped growing at 57% of the scale,
// because level 4 of 7 was a full-height left column. Every reading above it
// looked the same.
func TestSparklineHeightGrowsAcrossTheWholeScale(t *testing.T) {
	seen := map[rune]float64{}
	var prevDots int
	for _, pct := range []float64{10, 30, 50, 70, 90, 100} {
		r := plainSpark([]float64{pct, pct}, 1, 100)[0]
		dots := 0
		for b := 0; b < 8; b++ {
			if (int(r)-brailleBase)&(1<<b) != 0 {
				dots++
			}
		}
		if dots < prevDots {
			t.Errorf("at %.0f%% the chart has FEWER dots (%d) than at the previous step (%d)", pct, dots, prevDots)
		}
		prevDots = dots
		seen[r] = pct
	}
	// 57% and 100% must not render identically, which is what the old ramp did.
	if plainSpark([]float64{57, 57}, 1, 100)[0] == plainSpark([]float64{100, 100}, 1, 100)[0] {
		t.Error("57% and 100% render the same glyph — the scale saturates early again")
	}
}

// Every level must include its column's BOTTOM dot: a bar that floats above the
// baseline is the inverted fill the old ramp had, and the bottom-right dot was
// never lit at any level at all.
func TestSparklineAlwaysRestsOnTheBaseline(t *testing.T) {
	const botLeft, botRight = 0x40, 0x80
	for level := 1; level <= brailleLevels; level++ {
		if int(brailleLeftBits[level])&botLeft == 0 {
			t.Errorf("left level %d does not touch the baseline: %#x", level, brailleLeftBits[level])
		}
		if int(brailleRightBits[level])&botRight == 0 {
			t.Errorf("right level %d does not touch the baseline: %#x", level, brailleRightBits[level])
		}
	}
	// Full scale on both samples is a solid cell, with no notch anywhere.
	if got := plainSpark([]float64{100, 100}, 1, 100)[0]; got != '⣿' {
		t.Errorf("full scale renders %q, want ⣿", string(got))
	}
}

// A process using a little is not a process using none. Flooring alone drew 1%
// of a core as an empty chart, which reads as idle rather than as quiet.
func TestSparklineNeverDrawsASmallValueAsEmpty(t *testing.T) {
	if got := plainSpark([]float64{0.4, 0.4}, 1, 100)[0]; got == rune(brailleBase) {
		t.Error("0.4% rendered as an empty cell — an idle process and a quiet one must not look alike")
	}
	if got := plainSpark([]float64{0, 0}, 1, 100)[0]; got != rune(brailleBase) {
		t.Errorf("zero should be empty, got %q", string(got))
	}
}

// Each cell carries two samples, so the newest reading must sit in the
// right-hand column of the last cell rather than drifting as the series grows.
func TestSparklineKeepsTheNewestSampleAtTheRightEdge(t *testing.T) {
	for n := 1; n <= 8; n++ {
		data := make([]float64, n)
		data[n-1] = 100 // only the newest is hot
		r := plainSpark(data, 4, 100)
		if len(r) != 4 {
			t.Fatalf("n=%d: got %d cells, want 4", n, len(r))
		}
		if int(r[3])&int(brailleRightBits[brailleLevels]) != int(brailleRightBits[brailleLevels]) {
			t.Errorf("n=%d: the newest sample is not in the last cell's right column (%q)", n, string(r[3]))
		}
	}
}

func TestSparklineRespectsItsWidth(t *testing.T) {
	data := make([]float64, 500)
	for i := range data {
		data[i] = float64(i % 100)
	}
	for _, w := range []int{1, 7, 40, 120} {
		if got := lipgloss.Width(SparklineWithMax(data, w, 100, ColorGreen)); got != w {
			t.Errorf("width %d rendered %d", w, got)
		}
	}
	if got := SparklineWithMax(nil, 5, 100, ColorGreen); lipgloss.Width(got) != 5 {
		t.Errorf("an empty series should still fill its width, got %d", lipgloss.Width(got))
	}
	if strings.Contains(SparklineWithMax(nil, 5, 0, ColorGreen), "\n") {
		t.Error("a sparkline is one line")
	}
}
