package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Braille sparklines: two samples per cell, each column filled from the bottom.
//
// ─── Why not eight levels in one column ─────────────────────────────────────
//
// The previous ramp was ' ⡀⡄⡆⡇⡏⡟⡿', documented as "8-level per column". A
// braille cell is FOUR rows tall, so eight vertical levels in one column do not
// exist, and what that ramp actually did was spill the top half of the scale
// into the second column — which is a horizontal axis. Three consequences, all
// of them visible on screen:
//
//   - HEIGHT SATURATED AT 57%. Level 4 of 7 is '⡇', a full-height left column.
//     Every value from 57% to 100% already looked full, so the height of the
//     chart stopped meaning anything at the middle of the scale.
//   - THE TOP HALF FILLED DOWNWARDS. Levels 5, 6 and 7 lit top-right, then
//     upper-middle-right, then lower-middle-right: new mass appeared at the TOP
//     and grew down, while the bottom half of the scale grew up from the floor.
//   - THE BOTTOM-RIGHT DOT WAS NEVER LIT, at any level, so a full-scale reading
//     rendered with a permanent notch along its own baseline.
//
// So the second column becomes what it is shaped like — another sample. Each
// cell now carries two consecutive readings, each filling its own column from
// the bottom up. That is four honest vertical levels instead of eight false
// ones, and twice the time resolution in the same width, which is the trade
// worth making: a sparkline's job is to show the shape of a series over time.
//
// The alternative, if vertical resolution ever matters more than time, is the
// half-block ramp ▁▂▃▄▅▆▇█ — eight real levels, one sample per cell.

// brailleLeftBits and brailleRightBits give the dot mask for one column filled
// to level 0..4, bottom-up. Left column dots are 7,3,2,1 from the bottom
// (0x40, 0x04, 0x02, 0x01); right column dots are 8,6,5,4 (0x80, 0x20, 0x10,
// 0x08). Both include their bottom dot at level 1, which is what the old ramp
// never did for the right column.
var (
	brailleLeftBits  = [brailleLevels + 1]rune{0, 0x40, 0x44, 0x46, 0x47}
	brailleRightBits = [brailleLevels + 1]rune{0, 0x80, 0xA0, 0xB0, 0xB8}
)

const (
	// brailleLevels is how many vertical steps one column has. Four, because
	// that is how many rows a braille cell has.
	brailleLevels = 4
	// brailleSamplesPerCell is the horizontal resolution the second column
	// buys back.
	brailleSamplesPerCell = 2
	// brailleBase is U+2800, the empty braille pattern.
	brailleBase = 0x2800
)

// brailleCell composes one cell from two sample levels.
func brailleCell(left, right int) rune {
	return rune(brailleBase) | brailleLeftBits[left] | brailleRightBits[right]
}

// brailleLevel maps a value onto 0..brailleLevels.
//
// A non-zero value never renders as empty: flooring alone turned a process
// using 1% of a core into a blank chart, which reads as an idle process rather
// than as a quiet one — the same misreading #108 was about, in the sparkline.
func brailleLevel(v, maxScale float64) int {
	if v <= 0 || maxScale <= 0 {
		return 0
	}
	level := int(v / maxScale * brailleLevels)
	if level < 1 {
		level = 1
	}
	if level > brailleLevels {
		level = brailleLevels
	}
	return level
}

// Sparkline renders a data series as a colored braille chart,
// auto-scaling to the window's largest value. NOTE: using this variant
// causes the scale to change every tick — producing visual "everything jumping".
// For fixed scale (CPU at 0-100, IO with decay) prefer SparklineWithMax.
func Sparkline(data []float64, width int, color lipgloss.Color) string {
	max := 0.0
	for _, v := range data {
		if v > max {
			max = v
		}
	}
	return SparklineWithMax(data, width, max, color)
}

// SparklineWithMax uses an external maximum to normalize the series.
// Pass maxScale=100 for CPU%, or a slow-decay maximum for IO/counters.
// maxScale<=0 falls back to a blank chart with a visual floor.
//
// width is in CELLS, and each cell holds brailleSamplesPerCell readings — so a
// chart w columns wide shows the last 2w samples, and a series shorter than
// that is padded on the left, keeping the newest reading against the right edge.
func SparklineWithMax(data []float64, width int, maxScale float64, color lipgloss.Color) string {
	if width <= 0 {
		return ""
	}
	empty := string(rune(brailleBase))
	if len(data) == 0 || maxScale <= 0 {
		return lipgloss.NewStyle().Foreground(ColorDim).Render(strings.Repeat(empty, width))
	}

	want := width * brailleSamplesPerCell
	points := data
	if len(points) > want {
		points = points[len(points)-want:]
	}
	// Left-pad to a whole number of cells so the newest sample lands in the
	// right-hand column of the last cell rather than drifting between the two
	// as the series grows.
	pad := want - len(points)

	style := lipgloss.NewStyle().Foreground(color).Background(ColorPanel)
	dimStyle := lipgloss.NewStyle().Foreground(ColorDim).Background(ColorPanel)

	at := func(i int) float64 {
		if i < pad {
			return 0
		}
		return points[i-pad]
	}

	var sb strings.Builder
	for c := 0; c < width; c++ {
		l := brailleLevel(at(c*2), maxScale)
		r := brailleLevel(at(c*2+1), maxScale)
		ch := string(brailleCell(l, r))
		if l == 0 && r == 0 {
			sb.WriteString(dimStyle.Render(ch))
		} else {
			sb.WriteString(style.Render(ch))
		}
	}
	return sb.String()
}

// DualSparkline renders two stacked series (e.g. read/write).
// Series `a` uses `colorA`, series `b` uses `colorB`.
// Returns two lines separated by \n.
func DualSparkline(a, b []float64, width int, colorA, colorB lipgloss.Color) string {
	return Sparkline(a, width, colorA) + "\n" + Sparkline(b, width, colorB)
}

// HorizontalBar renders a proportional horizontal bar.
//
//	value:   current value
//	max:     maximum value (fixed — always pass the same between frames to
//	         avoid bars jumping size every tick)
//	width:   total width in columns
//	color:   color of the filled part
func HorizontalBar(value, max float64, width int, color lipgloss.Color) string {
	if width <= 0 {
		return ""
	}
	if max <= 0 {
		return lipgloss.NewStyle().Foreground(ColorDim).Background(ColorPanel).Render(strings.Repeat("░", width))
	}
	if value < 0 {
		value = 0
	}
	if value > max {
		value = max
	}
	filled := int((value / max) * float64(width))
	if filled > width {
		filled = width
	}
	full := strings.Repeat("█", filled)
	empty := strings.Repeat("░", width-filled)
	return lipgloss.NewStyle().Foreground(color).Background(ColorPanel).Render(full) +
		lipgloss.NewStyle().Foreground(ColorDim).Background(ColorPanel).Render(empty)
}
