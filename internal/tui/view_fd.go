package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/trentas/ptop/pkg/collector"
)

// renderFDView (F6) — assets/mockup.jsx → FDView
//
// Layout:
//
//	┌── FD Count Over Time (left) ─┬── Breakdown ─────┐
//	│ sparkline + value           │ file ▇▇▇  6       │
//	└─────────────────────────────┴───────────────────┘
//	filter chips: [all][file][socket][pipe][epoll][timer]
//	┌── FD table ─────────────────────────────────────┐
//	│ FD TYPE DESC FLAGS BYTES AGE ●                  │
//	│ ...                                             │
//	├── Alerts ───┬── Stats ─────┬── FD Events ──────┤
func renderFDView(m Model, w, h int) string {
	if w < minTerminalWidth || h < minContentHeight {
		return MutedStyle.Render("(terminal too small)")
	}
	if reason, none := m.noSource(srcFDs); none {
		return noSourcePanel("File Descriptors", reason, w, h)
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

	// filter chips occupy 1 line
	filterRow := renderFDFilterRow(m, leftW)
	filterH := lipgloss.Height(filterRow)

	// table takes the rest
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

	alertsPanel := Panel("Alerts", renderFDAlerts(m), rightW, rightHs[0])
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
	return lipgloss.JoinHorizontal(lipgloss.Top, spark, panelSp2, right)
}

func renderFDFilterRow(m Model, w int) string {
	pieces := []string{}
	selected := -1
	counts := fdBreakdownCounts(m.FDs)
	// A type with no fd gets no chip, unless it is the active filter: seven
	// types do not fit beside each other, and an empty chip would push out
	// the one holding most of the fds.
	chips := []string{"all"}
	for _, t := range fdTypeOrder {
		if counts[t] > 0 || t == m.FDFilter {
			chips = append(chips, t)
		}
	}
	for i, t := range chips {
		if t == m.FDFilter {
			selected = i
		}
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
	// Drop chips that do not fit, rather than letting the row run past w.
	//
	// The gap clamp below stops the PADDING going negative, which is not the
	// same thing as the row fitting: at 80 columns the chips came to 6 more
	// than the width, the line wrapped, and the whole FD tab slid down a row.
	// This is the same priority-dropping the header uses, with one extra rule —
	// the SELECTED chip is always kept, since a filter row that hides which
	// filter is active is worse than a short one.
	kept, used, keptSelected := []string{}, 0, false
	for i, p := range pieces {
		pw := lipgloss.Width(p)
		if used+pw > w {
			break
		}
		kept, used = append(kept, p), used+pw
		if i == selected {
			keptSelected = true
		}
	}
	if !keptSelected && len(kept) > 0 && selected >= 0 {
		used -= lipgloss.Width(kept[len(kept)-1])
		kept[len(kept)-1] = pieces[selected]
		used += lipgloss.Width(pieces[selected])
	}

	row := lipgloss.JoinHorizontal(lipgloss.Top, kept...)
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
		lipgloss.NewStyle().Width(fdW).Background(ColorPanel).Render("FD") + " " +
			padRight("TYPE", typeW) + " " +
			padRight("DESCRIPTION", descW) + " " +
			padRight("FLAGS", flagsW) + " " +
			lipgloss.NewStyle().Width(bytesW).Background(ColorPanel).Align(lipgloss.Right).Render("OFFSET") + " " +
			lipgloss.NewStyle().Width(ageW).Background(ColorPanel).Align(lipgloss.Right).Render("AGE") + " " +
			lipgloss.NewStyle().Width(dotW).Background(ColorPanel).Render(""),
	)

	// filter: first by type (cyclic FDFilter), then by substring
	// (m.filter, from `/` input mode).
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
		isSuspect := fdHeldInTmp(f)

		fdNum := lipgloss.NewStyle().Foreground(ColorMuted).Background(ColorPanel).Bold(true).Width(fdW).Render(fmt.Sprintf("%d", f.FD))
		typeStr := lipgloss.NewStyle().Foreground(FDTypeColor(f.Type)).Background(ColorPanel).Width(typeW).Render(FDTypeIcon(f.Type) + " " + f.Type)

		descColor := ColorText
		if f.Active {
			descColor = ColorBright
		}
		descStr := lipgloss.NewStyle().Foreground(descColor).Background(ColorPanel).Width(descW).Render(truncate(f.Desc, descW))

		flagsStr := lipgloss.NewStyle().Foreground(ColorDim).Background(ColorPanel).Width(flagsW).Render(f.Flags)
		// The offset and the activity dot are readings only where the fd has
		// an offset (PosKnown): a socket's never moves, and macOS has none.
		offset, offsetColor := "—", ColorDim
		if f.PosKnown {
			offset, offsetColor = fmtBytes(f.Bytes), ColorMuted
		}
		bytesStr := lipgloss.NewStyle().Foreground(offsetColor).Background(ColorPanel).Width(bytesW).Align(lipgloss.Right).Render(offset)

		ageColor := ColorDim
		if isOld {
			ageColor = ColorAmber
		}
		ageStr := lipgloss.NewStyle().Foreground(ageColor).Background(ColorPanel).Width(ageW).Align(lipgloss.Right).Render(fmtFDAge(f))

		var dot string
		switch {
		case !f.PosKnown:
			dot = lipgloss.NewStyle().Foreground(ColorDim).Background(ColorPanel).Render("—")
		case f.Active:
			dot = lipgloss.NewStyle().Foreground(ColorGreen).Background(ColorPanel).Render("●")
		default:
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

// fdHeldInTmp flags a file under /tmp held open for over ten minutes: a temp
// file that outlives the work it was made for is the usual shape of one that
// was never closed. It says how long the fd has been open and nothing about
// its activity, which no poll can vouch for over that span.
func fdHeldInTmp(f collector.FDEntry) bool {
	return f.Type == "file" && strings.HasPrefix(f.Desc, "/tmp/") && f.AgeMs > 600*1000
}

// fmtFDAge is an fd's age, marked "≥" when the fd was already open when ptop
// first looked: ptop knows only when it saw it.
func fmtFDAge(f collector.FDEntry) string {
	if f.Preexisting {
		return "≥" + fmtAgeMs(f.AgeMs)
	}
	return fmtAgeMs(f.AgeMs)
}

func renderFDAlerts(m Model) string {
	lines := []string{}
	for _, f := range m.FDs {
		if fdHeldInTmp(f) {
			lines = append(lines, AmberStyle.Render(
				fmt.Sprintf("⚠ fd=%d /tmp file open %s", f.FD, fmtFDAge(f)),
			))
		}
	}
	if lim := m.FDLimit; lim != nil && fdsNearLimit(len(m.FDs), lim.Soft) {
		lines = append(lines, RedStyle.Render(
			fmt.Sprintf("⚠ %d/%d fds open — %d%% of limit",
				len(m.FDs), lim.Soft, fdLimitPct(len(m.FDs), lim.Soft)),
		))
	}
	if len(lines) == 0 {
		lines = append(lines, GreenStyle.Render("✓ nothing flagged"))
	}
	return strings.Join(lines, "\n")
}

// fdLimitAlertPct is where F6 starts calling the open count close to the
// target's soft RLIMIT_NOFILE. Past the soft limit open and accept fail with
// EMFILE, which a server usually meets as connections it can no longer take.
const fdLimitAlertPct = 80

// fdsNearLimit says whether open fds have reached fdLimitAlertPct of soft. An
// unlimited soft limit is never near.
func fdsNearLimit(open int, soft uint64) bool {
	if soft == collector.FDLimitUnlimited {
		return false
	}
	return uint64(open)*100 >= soft*fdLimitAlertPct
}

// fdLimitPct is open as a whole percentage of soft. A soft limit of 0 (no fd
// may be opened at all) reads 100.
func fdLimitPct(open int, soft uint64) uint64 {
	if soft == 0 {
		return 100
	}
	return uint64(open) * 100 / soft
}

// fmtFDOpen is the Stats panel's "Open / limit" value: the open count over
// the soft limit, "—" where no collector reads the limit.
func fmtFDOpen(open int, lim *collector.FDLimit) string {
	switch {
	case lim == nil:
		return fmt.Sprintf("%d / —", open)
	case lim.Soft == collector.FDLimitUnlimited:
		return fmt.Sprintf("%d / unlimited", open)
	default:
		return fmt.Sprintf("%d / %d", open, lim.Soft)
	}
}

// fmtFDActive is the Stats panel's "Active files" value: how many of the fds
// with an offset moved it in the last poll, over how many have one. "—" when
// none has: sockets and pipes have no offset to watch, and macOS exposes none.
func fmtFDActive(fds []collector.FDEntry) string {
	var active, known int
	for _, f := range fds {
		if f.PosKnown {
			known++
			if f.Active {
				active++
			}
		}
	}
	if known == 0 {
		return "—"
	}
	return fmt.Sprintf("%d / %d", active, known)
}

func renderFDStats(m Model, w int) string {
	counts := fdBreakdownCounts(m.FDs)
	var oldest collector.FDEntry
	for _, f := range m.FDs {
		if f.AgeMs > oldest.AgeMs {
			oldest = f
		}
	}

	rows := []struct {
		label string
		value string
		color lipgloss.Color
	}{
		{"Open / limit", fmtFDOpen(len(m.FDs), m.FDLimit), ColorTeal},
		{"Active files", fmtFDActive(m.FDs), ColorGreen},
		{"Sockets", fmt.Sprintf("%d", counts["socket"]), ColorBlue},
		{"Files", fmt.Sprintf("%d", counts["file"]), ColorCyan},
		{"Oldest", fmtFDAge(oldest), ColorAmber},
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
