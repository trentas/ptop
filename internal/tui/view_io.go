package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/trentas/ptop/pkg/collector"
)

// renderIOView (F5) — assets/mockup.jsx → IOView
//
//   ┌── Throughput (large left) ──┐  ┌── I/O Stats ────┐
//   │ dual sparkline              │  │ Total read ...  │
//   ├── Top Files ────────────────┤  ├── Anomalies ────┤
//   │ db /data/db   88KB ...      │  │ ⚠ fsyncs high   │
//   ├── Latency Distribution ─────┤  ├── I/O Events ───┤
//   │ <0.1ms ▇▇  42 / 28          │  │ 12:34 IO read … │
//   └─────────────────────────────┘  └─────────────────┘
func renderIOView(m Model, w, h int) string {
	if w < 50 || h < 12 {
		return MutedStyle.Render("(terminal too small)")
	}
	leftW := w * 22 / 32 // ratio 2.2 vs 1.0
	rightW := w - leftW

	leftHs := splitFlex([]float64{1.0, 2.5, 1.4}, h)
	rightHs := splitFlex([]float64{0.9, 0.5, 2.0}, h)

	throughput := Panel("Throughput — read (cyan) · write (orange)",
		renderIOLargeThroughput(m.IOStats, m.IOReadHist, m.IOWriteHist, m.ioMaxRead, m.ioMaxWrite, leftW-2, leftHs[0]-3),
		leftW, leftHs[0])

	topFiles := Panel("Top Files",
		renderIOTopFiles(m.IOStats.TopFiles, m.topFilesPaths, leftW-2, leftHs[1]-3),
		leftW, leftHs[1])

	latDist := Panel("Latency Distribution",
		renderIOLatencyDist(m.IOStats.LatencyBuckets, leftW-2, leftHs[2]-3),
		leftW, leftHs[2])

	stats := Panel("I/O Stats",
		renderIOStats(m.IOStats, rightW-2),
		rightW, rightHs[0])

	anomalies := Panel("Anomalies",
		renderIOAnomalies(m, rightW-2, rightHs[1]-3),
		rightW, rightHs[1])

	events := Panel("I/O Events",
		renderTimelineCompact(filterTimelineByCategory(m.Timeline, "io"), rightW-2, rightHs[2]-3),
		rightW, rightHs[2])

	left := lipgloss.JoinVertical(lipgloss.Left, throughput, topFiles, latDist)
	right := lipgloss.JoinVertical(lipgloss.Left, stats, anomalies, events)
	return lipgloss.JoinHorizontal(lipgloss.Top, left, right)
}

// stableTopFiles returns the files in the given order (paths), or order by
// ops if the list is empty. Files whose paths aren't in the list are
// ignored (they fell out of the top since the last refresh).
func stableTopFiles(files []collector.IOFileStats, displayPaths []string) []collector.IOFileStats {
	if len(displayPaths) == 0 {
		out := make([]collector.IOFileStats, len(files))
		copy(out, files)
		sort.Slice(out, func(i, j int) bool {
			return out[i].Reads+out[i].Writes > out[j].Reads+out[j].Writes
		})
		return out
	}
	byPath := make(map[string]collector.IOFileStats, len(files))
	for _, f := range files {
		byPath[f.Path] = f
	}
	out := make([]collector.IOFileStats, 0, len(displayPaths))
	for _, p := range displayPaths {
		if f, ok := byPath[p]; ok {
			out = append(out, f)
		}
	}
	return out
}

func ioFileTypeColor(t string) lipgloss.Color {
	switch t {
	case "db":
		return ColorPurple
	case "log":
		return ColorCyan
	case "cfg":
		return ColorAmber
	case "tmp":
		return ColorMuted
	case "proc":
		return ColorPink
	default:
		return ColorMuted
	}
}

func renderIOTopFiles(files []collector.IOFileStats, displayPaths []string, w, h int) string {
	if len(files) == 0 {
		return MutedStyle.Render("(no data)")
	}
	// If we have a stable order from the model, use it; otherwise sort
	// by ops (used only on the first frame, before the model refresh).
	sorted := stableTopFiles(files, displayPaths)

	const typeW = 5
	const opsW = 6
	const bytesW = 9
	const latW = 8
	const fsyncW = 7
	pathW := w - typeW - opsW - bytesW - latW - fsyncW - 5
	if pathW < 12 {
		pathW = 12
	}

	header := MutedStyle.Render(
		padRight("TYPE", typeW) + " " +
			padRight("PATH", pathW) + " " +
			lipgloss.NewStyle().Width(opsW).Background(ColorPanel).Align(lipgloss.Right).Render("OPS") + " " +
			lipgloss.NewStyle().Width(bytesW).Background(ColorPanel).Align(lipgloss.Right).Render("BYTES") + " " +
			lipgloss.NewStyle().Width(latW).Background(ColorPanel).Align(lipgloss.Right).Render("LAT") + " " +
			lipgloss.NewStyle().Width(fsyncW).Background(ColorPanel).Align(lipgloss.Right).Render("FSYNC"),
	)

	maxOps := uint64(1)
	for _, f := range sorted {
		if f.Reads+f.Writes > maxOps {
			maxOps = f.Reads + f.Writes
		}
	}

	lines := []string{header}
	for _, f := range sorted {
		if h > 0 && len(lines) >= h {
			break
		}
		ops := f.Reads + f.Writes
		typeColor := ioFileTypeColor(f.Type)

		typeStr := lipgloss.NewStyle().Foreground(typeColor).Background(ColorPanel).Width(typeW).Render(f.Type)
		path := lipgloss.NewStyle().Foreground(ColorText).Background(ColorPanel).Width(pathW).Render(truncate(f.Path, pathW))
		opsStr := lipgloss.NewStyle().Foreground(ColorBright).Background(ColorPanel).Width(opsW).Align(lipgloss.Right).Render(fmt.Sprintf("%d", ops))
		bytesStr := lipgloss.NewStyle().Foreground(ColorMuted).Background(ColorPanel).Width(bytesW).Align(lipgloss.Right).Render(fmtBytes(f.Bytes))

		latColor := ColorGreen
		if f.LatencyMs > 1 {
			latColor = ColorAmber
		}
		if f.LatencyMs > 5 {
			latColor = ColorRed
		}
		latStr := lipgloss.NewStyle().Foreground(latColor).Background(ColorPanel).Width(latW).Align(lipgloss.Right).Render(fmt.Sprintf("%.1fms", f.LatencyMs))

		fsyncColor := ColorDim
		fsyncLabel := "–"
		if f.Fsyncs > 0 {
			fsyncLabel = fmt.Sprintf("%d ⚡", f.Fsyncs)
			fsyncColor = ColorAmber
		}
		if f.Fsyncs > 10 {
			fsyncColor = ColorRed
		}
		fsyncStr := lipgloss.NewStyle().Foreground(fsyncColor).Background(ColorPanel).Width(fsyncW).Align(lipgloss.Right).Render(fsyncLabel)

		lines = append(lines, panelRow(typeStr, path, opsStr, bytesStr, latStr, fsyncStr))

	}
	return strings.Join(lines, "\n")
}

func renderIOLatencyDist(buckets []collector.LatencyBucket, w, h int) string {
	if len(buckets) == 0 {
		return MutedStyle.Render("(no data)")
	}
	maxV := 1.0
	for _, b := range buckets {
		if b.Read > maxV {
			maxV = b.Read
		}
		if b.Write > maxV {
			maxV = b.Write
		}
	}
	const labelW = 9
	const numW = 5
	barW := w - labelW - numW*2 - 4
	if barW < 8 {
		barW = 8
	}
	lines := []string{}
	for _, b := range buckets {
		if h > 0 && len(lines) >= h {
			break
		}
		label := lipgloss.NewStyle().Foreground(ColorMuted).Background(ColorPanel).Width(labelW).Render(b.Label)
		readBar := HorizontalBar(b.Read, maxV, barW, ColorCyan)
		writeBar := HorizontalBar(b.Write, maxV, barW, ColorOrange)
		readNum := lipgloss.NewStyle().Foreground(ColorCyan).Background(ColorPanel).Width(numW).Align(lipgloss.Right).Render(fmt.Sprintf("%.0f", b.Read))
		writeNum := lipgloss.NewStyle().Foreground(ColorOrange).Background(ColorPanel).Width(numW).Align(lipgloss.Right).Render(fmt.Sprintf("%.0f", b.Write))

		stack := lipgloss.JoinVertical(lipgloss.Left,
			lipgloss.JoinHorizontal(lipgloss.Top, label, panelSp1, readBar, panelSp1, readNum),
			lipgloss.JoinHorizontal(lipgloss.Top, padRight("", labelW), panelSp1, writeBar, panelSp1, writeNum),
		)
		lines = append(lines, stack)
	}
	return strings.Join(lines, "\n")
}

func renderIOStats(s collector.IOStats, w int) string {
	rows := []struct {
		label string
		value string
		color lipgloss.Color
	}{
		{"Total read", fmtBytesPerSec(s.ReadBytesPerS), ColorCyan},
		{"Total write", fmtBytesPerSec(s.WriteBytesPerS), ColorOrange},
		{"Read ops", fmt.Sprintf("%d", s.ReadOps), ColorCyan},
		{"Write ops", fmt.Sprintf("%d", s.WriteOps), ColorOrange},
		{"fsyncs", fmt.Sprintf("%d", s.Fsyncs), thresholdColor(float64(s.Fsyncs), 20)},
		{"File opens", fmt.Sprintf("%d", s.Opens), ColorMuted},
		{"I/O wait", fmt.Sprintf("%.1f%%", s.IOWaitPct), thresholdColor(s.IOWaitPct, 15)},
	}
	lines := []string{}
	for _, r := range rows {
		left := MutedStyle.Render(r.label)
		right := lipgloss.NewStyle().Foreground(r.color).Background(ColorPanel).Render(r.value)
		gap := w - lipgloss.Width(left) - lipgloss.Width(right)
		if gap < 1 {
			gap = 1
		}
		lines = append(lines, left+panelGap(gap)+right)
	}
	return strings.Join(lines, "\n")
}

// renderIOAnomalies surfaces, newest-first: real permission denials (#57, only
// the eBPF io collector emits them), then the IOStats-derived fsync/I/O-wait
// threshold anomalies. The "/proc/self/status polling" heuristic is simulated,
// so it only appears in mock mode. With a real source and nothing wrong, it
// honestly reports a healthy filesystem rather than inventing a warning.
func renderIOAnomalies(m Model, w, h int) string {
	lines := []string{}
	room := func() bool { return h <= 0 || len(lines) < h }

	// Permission denials are the headline anomaly. Deletes/renames are events,
	// not anomalies — they flow to the I/O Events feed, not here.
	for _, e := range m.FSEvents {
		if e.Op != "denied" || !room() {
			continue
		}
		style := lipgloss.NewStyle().Foreground(fsEventColor(e.Op)).Background(ColorPanel)
		lines = append(lines, style.Render(truncate("⚠ "+fsEventMessage(e), w)))
	}

	s := m.IOStats
	if s.Fsyncs > 15 && room() {
		lines = append(lines, RedStyle.Render("⚠ high fsync freq → /data/db"))
	}
	if s.IOWaitPct > 15 && room() {
		lines = append(lines, RedStyle.Render(fmt.Sprintf("⚠ I/O wait %.1f%% → disk saturated", s.IOWaitPct)))
	}
	if m.usingMockIOFiles && room() {
		lines = append(lines, AmberStyle.Render("⚠ /proc/self/status: polling (×12/s)"))
	}

	if len(lines) == 0 {
		if m.usingMockIOFiles {
			return GreenStyle.Render("✓ throughput stable")
		}
		return GreenStyle.Render("✓ no permission denials")
	}
	return strings.Join(lines, "\n")
}

// fsEventMessage renders an FSEvent as a one-line cause + path(s), used both by
// the F5 Anomalies panel (denials) and the synthesized I/O-timeline entry
// (every fs event).
func fsEventMessage(e collector.FSEvent) string {
	switch e.Op {
	case "denied":
		return fmt.Sprintf("denied %s (%s)", e.Path, e.Err)
	case "deleted":
		if e.Errno != 0 {
			return fmt.Sprintf("delete failed %s (%s)", e.Path, e.Err)
		}
		return fmt.Sprintf("deleted %s", e.Path)
	case "renamed":
		if e.Errno != 0 {
			return fmt.Sprintf("rename failed %s → %s (%s)", e.Path, e.NewPath, e.Err)
		}
		return fmt.Sprintf("renamed %s → %s", e.Path, e.NewPath)
	default:
		return fmt.Sprintf("%s %s", e.Op, e.Path)
	}
}

// fsEventColor maps an fs op to a severity color: a denial is red (a blocked
// access), a delete amber (destructive), a rename muted (benign bookkeeping).
func fsEventColor(op string) lipgloss.Color {
	switch op {
	case "denied":
		return ColorRed
	case "deleted":
		return ColorAmber
	default:
		return ColorMuted
	}
}

func thresholdColor(value, warn float64) lipgloss.Color {
	switch {
	case value > warn*2:
		return ColorRed
	case value > warn:
		return ColorAmber
	default:
		return ColorGreen
	}
}
