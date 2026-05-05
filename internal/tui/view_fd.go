package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/trentas/xray/internal/collector"
)

// renderFDView (F6) — assets/mockup.jsx → FDView
//
// Layout:
//
//   ┌── FD Count Over Time (esq) ─┬── Breakdown ──────┐
//   │ sparkline + valor           │ file ▇▇▇  6       │
//   └─────────────────────────────┴───────────────────┘
//   filter chips: [all][file][socket][pipe][epoll][timer]
//   ┌── FD table ─────────────────────────────────────┐
//   │ FD TYPE DESC FLAGS BYTES AGE ●                  │
//   │ ...                                             │
//   ├── Alertas ──┬── Stats ─────┬── FD Events ──────┤
func renderFDView(m Model, w, h int) string {
	if w < 50 || h < 12 {
		return MutedStyle.Render("(terminal pequeno demais)")
	}

	leftW := w * 25 / 35 // ratio 2.5 : 1.0
	rightW := w - leftW

	// === LEFT COLUMN ============================================================
	// Top row: FD Count Over Time + Breakdown
	topH := splitFlex([]float64{1.0}, h)[0]
	if topH > 6 {
		topH = 6
	}
	if topH < 4 {
		topH = 4
	}

	// filter chips ocupa 1 linha
	filterRow := renderFDFilterRow(m, leftW)
	filterH := lipgloss.Height(filterRow)

	// table ocupa o resto
	tableH := h - topH - filterH
	if tableH < 4 {
		tableH = 4
	}

	sparkW := (leftW * 2) / 3
	breakdownW := leftW - sparkW

	sparkPanel := Panel("FD Count Over Time",
		renderFDCountSparkline(m, sparkW-2),
		sparkW, topH)

	breakdownPanel := Panel("Breakdown",
		renderFDMini(m.FDs, breakdownW-2),
		breakdownW, topH)

	topRow := lipgloss.JoinHorizontal(lipgloss.Top, sparkPanel, breakdownPanel)

	tablePanel := PanelTitleless(renderFDTable(m, leftW-2, tableH-2), leftW, tableH)

	leftCol := lipgloss.JoinVertical(lipgloss.Left, topRow, filterRow, tablePanel)

	// === RIGHT COLUMN ===========================================================
	rightHs := splitFlex([]float64{0.7, 0.7, 2.0}, h)

	alertsPanel := Panel("Alertas", renderFDAlerts(m), rightW, rightHs[0])
	statsPanel := Panel("Stats", renderFDStats(m, rightW-2), rightW, rightHs[1])
	eventsPanel := Panel("FD Events",
		renderFDEvents(m.FDEvents, rightW-2, rightHs[2]-3),
		rightW, rightHs[2])

	rightCol := lipgloss.JoinVertical(lipgloss.Left, alertsPanel, statsPanel, eventsPanel)

	return lipgloss.JoinHorizontal(lipgloss.Top, leftCol, rightCol)
}

func renderFDCountSparkline(m Model, w int) string {
	cur := 0
	if len(m.FDs) > 0 {
		cur = len(m.FDs)
	}
	rightW := 10
	sparkW := w - rightW - 2
	if sparkW < 5 {
		sparkW = 5
	}
	spark := Sparkline(m.FDCountHistory, sparkW, ColorTeal)
	val := lipgloss.NewStyle().Foreground(ColorTeal).Background(ColorPanel).Bold(true).Width(rightW).Align(lipgloss.Right).Render(fmt.Sprintf("%d", cur))
	lbl := lipgloss.NewStyle().Foreground(ColorMuted).Background(ColorPanel).Width(rightW).Align(lipgloss.Right).Render("open fds")
	right := val + "\n" + lbl
	return lipgloss.JoinHorizontal(lipgloss.Top, spark, "  ", right)
}

func renderFDFilterRow(m Model, w int) string {
	pieces := []string{}
	counts := fdBreakdownCounts(m.FDs)
	for _, t := range append([]string{"all"}, fdTypeOrder...) {
		var label string
		if t == "all" {
			label = fmt.Sprintf("all (%d)", len(m.FDs))
		} else {
			label = fmt.Sprintf("%s (%d)", t, counts[t])
		}
		var style lipgloss.Style
		if t == m.FDFilter {
			style = lipgloss.NewStyle().
				Foreground(ColorTeal).
				Background(ColorPanel).
				Padding(0, 2).
				Bold(true)
		} else {
			style = lipgloss.NewStyle().
				Foreground(ColorMuted).
				Background(ColorBG).
				Padding(0, 2)
		}
		pieces = append(pieces, style.Render(label))
	}
	row := lipgloss.JoinHorizontal(lipgloss.Top, pieces...)
	gap := w - lipgloss.Width(row)
	if gap < 0 {
		gap = 0
	}
	return row + lipgloss.NewStyle().Background(ColorBG).Render(strings.Repeat(" ", gap))
}

func renderFDTable(m Model, w, h int) string {
	const fdW = 4
	const typeW = 8
	const flagsW = 10
	const bytesW = 9
	const ageW = 6
	const dotW = 2
	descW := w - fdW - typeW - flagsW - bytesW - ageW - dotW - 6
	if descW < 12 {
		descW = 12
	}

	header := MutedStyle.Render(
		lipgloss.NewStyle().Width(fdW).Render("FD") + " " +
			padRight("TYPE", typeW) + " " +
			padRight("DESCRIPTION", descW) + " " +
			padRight("FLAGS", flagsW) + " " +
			lipgloss.NewStyle().Width(bytesW).Align(lipgloss.Right).Render("BYTES") + " " +
			lipgloss.NewStyle().Width(ageW).Align(lipgloss.Right).Render("AGE") + " " +
			lipgloss.NewStyle().Width(dotW).Render(""),
	)

	// filtra: primeiro por tipo (FDFilter cíclico), depois por substring
	// (m.filter, vindo do input mode `/`).
	filtered := m.FDs
	if m.FDFilter != "all" && m.FDFilter != "" {
		next := make([]collector.FDEntry, 0, len(m.FDs))
		for _, f := range m.FDs {
			if f.Type == m.FDFilter {
				next = append(next, f)
			}
		}
		filtered = next
	}
	if m.filter != "" {
		next := make([]collector.FDEntry, 0, len(filtered))
		for _, f := range filtered {
			if strings.Contains(strings.ToLower(f.Desc), strings.ToLower(m.filter)) {
				next = append(next, f)
			}
		}
		filtered = next
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].FD < filtered[j].FD })

	rows := []string{header, DimStyle.Render(strings.Repeat("─", w))}
	for _, f := range filtered {
		if h > 0 && len(rows) >= h {
			break
		}

		isOld := f.AgeMs > 3600*1000
		isSuspect := f.Type == "file" && strings.Contains(f.Desc, "/tmp") && f.AgeMs > 600*1000

		fdNum := lipgloss.NewStyle().Foreground(ColorMuted).Background(ColorPanel).Bold(true).Width(fdW).Render(fmt.Sprintf("%d", f.FD))
		typeStr := lipgloss.NewStyle().Foreground(FDTypeColor(f.Type)).Background(ColorPanel).Width(typeW).Render(FDTypeIcon(f.Type) + " " + f.Type)

		descColor := ColorText
		if f.Active {
			descColor = ColorBright
		}
		descStr := lipgloss.NewStyle().Foreground(descColor).Background(ColorPanel).Width(descW).Render(truncate(f.Desc, descW))

		flagsStr := lipgloss.NewStyle().Foreground(ColorDim).Background(ColorPanel).Width(flagsW).Render(f.Flags)
		bytesStr := lipgloss.NewStyle().Foreground(ColorMuted).Background(ColorPanel).Width(bytesW).Align(lipgloss.Right).Render(fmtBytes(f.Bytes))

		ageColor := ColorDim
		if isOld {
			ageColor = ColorAmber
		}
		ageStr := lipgloss.NewStyle().Foreground(ageColor).Background(ColorPanel).Width(ageW).Align(lipgloss.Right).Render(fmtAgeMs(f.AgeMs))

		var dot string
		if f.Active {
			dot = lipgloss.NewStyle().Foreground(ColorGreen).Background(ColorPanel).Render("●")
		} else {
			dot = lipgloss.NewStyle().Foreground(ColorDim).Background(ColorPanel).Render("○")
		}

		row := panelRow(fdNum, typeStr, descStr, flagsStr, bytesStr, ageStr, dot)
		if isSuspect {
			row = lipgloss.NewStyle().Background(lipgloss.Color("#1f1a08")).Render(row)
		}
		rows = append(rows, row)
	}
	return strings.Join(rows, "\n")
}

func renderFDAlerts(m Model) string {
	lines := []string{}
	suspect := 0
	for _, f := range m.FDs {
		if f.Type == "file" && strings.Contains(f.Desc, "/tmp") && f.AgeMs > 600*1000 {
			suspect++
			lines = append(lines, AmberStyle.Render(
				fmt.Sprintf("⚠ fd=%d %s aberto há %s sem atividade", f.FD, f.Type, fmtAgeMs(f.AgeMs)),
			))
		}
	}
	if len(m.FDs) > 20 {
		lines = append(lines, RedStyle.Render(
			fmt.Sprintf("⚠ %d fds abertos — próximo do limite", len(m.FDs)),
		))
	}
	if len(lines) == 0 {
		lines = append(lines, GreenStyle.Render("✓ sem vazamentos detectados"))
	}
	return strings.Join(lines, "\n")
}

func renderFDStats(m Model, w int) string {
	counts := fdBreakdownCounts(m.FDs)
	active := 0
	var totalBytes uint64
	var maxAge int64
	for _, f := range m.FDs {
		if f.Active {
			active++
		}
		totalBytes += f.Bytes
		if f.AgeMs > maxAge {
			maxAge = f.AgeMs
		}
	}

	rows := []struct {
		label string
		value string
		color lipgloss.Color
	}{
		{"Total abertos", fmt.Sprintf("%d", len(m.FDs)), ColorTeal},
		{"Ativos agora", fmt.Sprintf("%d", active), ColorGreen},
		{"Sockets", fmt.Sprintf("%d", counts["socket"]), ColorBlue},
		{"Files", fmt.Sprintf("%d", counts["file"]), ColorCyan},
		{"Mais antigo", fmtAgeMs(maxAge), ColorAmber},
		{"Total I/O", fmtBytes(totalBytes), ColorMuted},
	}
	lines := []string{}
	for _, r := range rows {
		left := MutedStyle.Render(r.label)
		right := lipgloss.NewStyle().Foreground(r.color).Background(ColorPanel).Render(r.value)
		gap := w - lipgloss.Width(left) - lipgloss.Width(right)
		if gap < 1 {
			gap = 1
		}
		lines = append(lines, left+strings.Repeat(" ", gap)+right)
	}
	return strings.Join(lines, "\n")
}

func renderFDEvents(events []collector.FDEvent, w, h int) string {
	if h <= 0 {
		return ""
	}
	visible := events
	if len(visible) > h {
		visible = visible[:h]
	}
	const tsW = 12
	msgW := w - tsW - 2
	if msgW < 8 {
		msgW = 8
	}
	lines := make([]string, 0, len(visible))
	for _, e := range visible {
		ts := lipgloss.NewStyle().Foreground(ColorDim).Background(ColorPanel).Width(tsW).Render(e.Timestamp.Format("15:04:05.000"))
		msg := lipgloss.NewStyle().Foreground(ColorText).Background(ColorPanel).Width(msgW).Render(truncate(e.Message, msgW))
		lines = append(lines, panelRow(ts, msg))

	}
	return strings.Join(lines, "\n")
}
