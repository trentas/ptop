package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// sourceProcOrEmpty returns the OS-appropriate non-eBPF source label
// ("/proc" on Linux, "libproc" on macOS) when the collector is running real,
// "" otherwise. Used to annotate the source in the help overlay.
func sourceProcOrEmpty(real bool) string {
	if real {
		return sourceProcEquivalent
	}
	return ""
}

// renderHelpOverlay draws a centered modal with all the keybindings.
// Receives the total content area dimensions; lipgloss.Place centers the card.
//
// The model is passed so we can show collector status at runtime
// (real vs mock) — issue #19 acceptance: "Key or flag to view the status of
// each collector at runtime".
func renderHelpOverlayWithStatus(m Model, w, h int) string {
	// Help overlay lives over the card's ColorPanel. All the styles below
	// set ColorPanel as bg so segments don't leak the terminal's background
	// between words.
	sectionTitle := lipgloss.NewStyle().Foreground(ColorCyan).Background(ColorPanel).Bold(true)
	keyStyle := lipgloss.NewStyle().Foreground(ColorTeal).Background(ColorPanel).Bold(true)
	descStyle := lipgloss.NewStyle().Foreground(ColorText).Background(ColorPanel)
	dimDesc := lipgloss.NewStyle().Foreground(ColorMuted).Background(ColorPanel)

	row := func(key, desc string) string {
		return keyStyle.Render(padRight(key, 14)) + descStyle.Render(" "+desc)
	}
	dimRow := func(key, desc string) string {
		return keyStyle.Render(padRight(key, 14)) + dimDesc.Render(" "+desc)
	}

	statusReal := lipgloss.NewStyle().Foreground(ColorGreen).Background(ColorPanel).Render("● real")
	statusMock := lipgloss.NewStyle().Foreground(ColorAmber).Background(ColorPanel).Render("○ mock")
	statusNA := lipgloss.NewStyle().Foreground(ColorRed).Background(ColorPanel).Render("✕ unavailable")
	sourceStyle := lipgloss.NewStyle().Foreground(ColorMuted).Background(ColorPanel).Italic(true)

	// statusRowNA renders a subsystem that is structurally unavailable on
	// this OS (e.g. syscalls on macOS Tier 1). Distinct from "mock" because
	// no user toggle can flip it to real — it's a platform limitation.
	statusRowNA := func(name, reason string) string {
		row := keyStyle.Render(padRight(name, 14)) + descStyle.Render(" ") + statusNA
		if reason != "" {
			row += sourceStyle.Render(" — " + reason)
		}
		return row
	}

	statusRow := func(name string, isMock bool, source string) string {
		s := statusReal
		if isMock {
			s = statusMock
		}
		row := keyStyle.Render(padRight(name, 14)) + descStyle.Render(" ") + s
		if source != "" {
			row += sourceStyle.Render(" via " + source)
		}
		return row
	}

	// statusRowMaybeNA picks between the "unavailable" rendering (when
	// the build target has no Tier 1 path for this subsystem) and the
	// regular real/mock row.
	statusRowMaybeNA := func(name string, unavailable bool, naReason string, isMock bool, source string) string {
		if unavailable {
			return statusRowNA(name, naReason)
		}
		return statusRow(name, isMock, source)
	}

	lines := []string{
		sectionTitle.Render("Navigation"),
		row("F1-F7", "Switch tab"),
		row("1-7", "Tab shortcut (alternative to F1-F7)"),
		row("Tab", "Next tab"),
		row("Shift+Tab", "Previous tab"),
		"",
		sectionTitle.Render("Filter"),
		row("/", "Open substring filter (or cycle types in F6 when empty)"),
		row("Enter", "Confirm filter"),
		row("Esc", "Cancel input · or clear filter · or close help"),
		row("Ctrl+U", "Clear what's being typed"),
		"",
		sectionTitle.Render("State"),
		row("p, Space", "Pause / resume simulation"),
		row("?", "Open / close this screen"),
		row("q, Ctrl+C", "Quit"),
		"",
		sectionTitle.Render("Snapshot / Export"),
		row("s", "One-shot snapshot (ptop-snapshot-<ts>.json)"),
		row("e", "Toggle continuous export (ptop-export-<ts>.jsonl)"),
		dimRow("--export", "CLI flag: export from launch + final snapshot on exit"),
		"",
		sectionTitle.Render("Collectors"),
		statusRowMaybeNA("syscalls", syscallsUnavailable, "no public per-syscall trace on macOS (see #22)",
			m.usingMockSyscalls, m.syscallsSource),
		statusRow("cpu", m.usingMockCPU, m.cpuSource),
		statusRowMaybeNA("io-files", ioFilesUnavailable, "no public per-file VFS hook on macOS (see #22)",
			m.usingMockIOFiles, m.ioFilesSource),
		statusRow("network", m.usingMockNet, m.netSource),
		statusRow("memory", m.usingMockMem, m.memSource),
		// Heap (malloc/free) is eBPF-only and never simulated: it's "real via
		// eBPF" when the libc uprobes attached, else genuinely unavailable
		// (macOS, --no-ebpf, or a static / non-libc target) — never "mock".
		func() string {
			if m.heapSource != "" {
				return statusRow("heap", false, m.heapSource)
			}
			return statusRowNA("heap", "needs eBPF + a libc-linked target")
		}(),
		statusRowMaybeNA("locks", locksUnavailable, "no public __ulock_wait hook on macOS (see #22)",
			m.locksSource == "", m.locksSource),
		// Signals (#58) are eBPF-only and never simulated: "real via eBPF" when
		// the signal_generate tracepoint attached, else genuinely unavailable
		// (macOS, --no-ebpf, or attach failure) — never "mock".
		func() string {
			if m.signalsSource != "" {
				return statusRow("signals", false, m.signalsSource)
			}
			return statusRowNA("signals", "needs eBPF (signal_generate tracepoint)")
		}(),
		// TLS payload (#55) is opt-in (--tls) and stream/export-only. "off" when
		// not requested; "real via eBPF (libssl)" when attached; "unavailable"
		// when requested but no libssl is mapped (Go/static target).
		func() string {
			if m.tlsSource != "" {
				return statusRow("tls", false, m.tlsSource+" (libssl)")
			}
			if m.cfg.TLS {
				return statusRowNA("tls", "no libssl mapped (Go/static target)")
			}
			return keyStyle.Render(padRight("tls", 14)) + descStyle.Render(" ") +
				lipgloss.NewStyle().Foreground(ColorMuted).Background(ColorPanel).Render("○ off") +
				sourceStyle.Render(" — enable with --tls")
		}(),
		statusRow("threads", m.usingMockThreads, m.threadsSource),
		statusRow("io-wait", m.usingMockIOWait, sourceProcOrEmpty(!m.usingMockIOWait)),
		statusRow("io-throughput", m.usingMockIOThrough, sourceProcOrEmpty(!m.usingMockIOThrough)),
		statusRow("fds", m.usingMockFDs, sourceProcOrEmpty(!m.usingMockFDs)),
		// Execution context (#60) is /proc-based and never simulated: "real via
		// /proc" when the namespace/cgroup collector started, else structurally
		// unavailable (macOS has no namespaces/cgroups).
		func() string {
			if m.contextSource != "" {
				return statusRow("context", false, m.contextSource)
			}
			return statusRowNA("context", "namespace/cgroup is Linux-only")
		}(),
	}

	// Scroll: card has border (2 lines) + padding (2 lines) = 4 overhead;
	// if there's still room for scroll indicators (2 lines), maxBody is
	// h - 4 - 2 = h - 6. On 80x24 terminals with chrome taking ~3 lines,
	// contentH ≈ 21, maxBody ≈ 15 — less than the ~30 lines of help. Scroll
	// is actually necessary.
	maxBody := h - 4
	if maxBody < 5 {
		maxBody = 5
	}

	scroll := m.helpScroll
	hasMoreAbove := false
	hasMoreBelow := false

	if len(lines) > maxBody {
		// reserves 2 lines for the scroll indicators
		bodyH := maxBody - 2
		if bodyH < 3 {
			bodyH = 3
		}
		// clamp scroll
		maxScroll := len(lines) - bodyH
		if scroll > maxScroll {
			scroll = maxScroll
		}
		if scroll < 0 {
			scroll = 0
		}
		hasMoreAbove = scroll > 0
		hasMoreBelow = scroll+bodyH < len(lines)
		lines = lines[scroll : scroll+bodyH]
	}

	scrollIndicator := func(visible bool, glyph, hint string) string {
		if !visible {
			return lipgloss.NewStyle().Foreground(ColorPanel).Background(ColorPanel).Render(strings.Repeat(" ", 30))
		}
		return lipgloss.NewStyle().Foreground(ColorTeal).Background(ColorPanel).Italic(true).
			Render(glyph + " " + hint)
	}

	if hasMoreAbove || hasMoreBelow {
		lines = append([]string{scrollIndicator(hasMoreAbove, "↑", "more above (↑/PgUp)")}, lines...)
		lines = append(lines, scrollIndicator(hasMoreBelow, "↓", "more below (↓/PgDn)"))
	}

	body := strings.Join(lines, "\n")

	card := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorCyan).
		Background(ColorPanel).
		Padding(1, 3).
		Render(body)

	// Centers the card over a darkened background. lipgloss.Place paints the
	// total area with the base color and positions the card in the center.
	return lipgloss.Place(w, h,
		lipgloss.Center, lipgloss.Center,
		card,
		lipgloss.WithWhitespaceBackground(ColorBG),
	)
}

// renderFilterInput draws the active input widget instead of the statusbar.
// Shows the cursor as a ▏ block at the end of the buffer. width = m.Width.
func renderFilterInput(m Model, w int) string {
	barBg := lipgloss.Color("#0a0d11")
	prompt := lipgloss.NewStyle().
		Foreground(ColorTeal).
		Background(barBg).
		Bold(true).
		Render(" / ")
	hint := lipgloss.NewStyle().
		Foreground(ColorDim).
		Background(barBg).
		Render(" Enter confirms · Esc cancels · Ctrl+U clears")

	cursor := lipgloss.NewStyle().Foreground(ColorBright).Background(barBg).Render("▏")
	value := lipgloss.NewStyle().Foreground(ColorBright).Background(barBg).Render(m.inputBuf)

	used := lipgloss.Width(prompt) + lipgloss.Width(value) + lipgloss.Width(cursor) + lipgloss.Width(hint)
	gap := w - used - 2
	if gap < 1 {
		gap = 1
	}
	pad := lipgloss.NewStyle().Background(barBg).Render(strings.Repeat(" ", gap))
	edge := lipgloss.NewStyle().Background(barBg).Render(" ")
	return edge + prompt + value + cursor + pad + hint + edge
}
