package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Braille block characters for sparkline (8 height levels per column).
// Each rune represents a vertical fill level: empty → full.
var brailleRamp = []rune{
	' ', '⡀', '⡄', '⡆', '⡇', '⡏', '⡟', '⡿',
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
func SparklineWithMax(data []float64, width int, maxScale float64, color lipgloss.Color) string {
	if width <= 0 {
		return ""
	}
	if len(data) == 0 || maxScale <= 0 {
		return lipgloss.NewStyle().Foreground(ColorDim).Render(strings.Repeat(string(brailleRamp[0]), width))
	}

	points := data
	if len(points) > width {
		points = points[len(points)-width:]
	}

	style := lipgloss.NewStyle().Foreground(color).Background(ColorPanel)
	dimStyle := lipgloss.NewStyle().Foreground(ColorDim).Background(ColorPanel)

	var sb strings.Builder

	// left padding when we still have fewer samples than available width
	for i := 0; i < width-len(points); i++ {
		sb.WriteString(dimStyle.Render(string(brailleRamp[0])))
	}

	for _, v := range points {
		level := int((v / maxScale) * float64(len(brailleRamp)-1))
		if level < 0 {
			level = 0
		}
		if level >= len(brailleRamp) {
			level = len(brailleRamp) - 1
		}
		ch := brailleRamp[level]
		if level == 0 {
			sb.WriteString(dimStyle.Render(string(ch)))
		} else {
			sb.WriteString(style.Render(string(ch)))
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
