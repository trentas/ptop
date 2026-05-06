package tui

import (
	"fmt"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
)

// fdFilters defines the cycling order when pressing '/' in the FD view (legacy mode
// when the substring filter is empty — pressing `/` again enters input mode).
var fdFilters = []string{"all", "file", "socket", "pipe", "epoll", "timer"}

// handleKey processes keyboard input.
//
// Priority order:
//  1. Help overlay open: any key closes
//  2. Input mode (filter) active: forwarding to inputBuf, with special Enter/Esc/Backspace
//  3. Global commands (F1-F7, q, p, etc)
func (m Model) handleKey(msg tea.KeyMsg) (Model, tea.Cmd) {
	key := msg.String()

	// 1. Help overlay
	if m.showHelp {
		switch key {
		case "up", "k":
			if m.helpScroll > 0 {
				m.helpScroll--
			}
		case "down", "j":
			m.helpScroll++ // capped by the view if it goes past the total
		case "pgup":
			m.helpScroll -= 10
			if m.helpScroll < 0 {
				m.helpScroll = 0
			}
		case "pgdown":
			m.helpScroll += 10
		case "home", "g":
			m.helpScroll = 0
		case "end", "G":
			m.helpScroll = 9999 // capped by the view
		case "?", "esc", "q":
			m.showHelp = false
			m.helpScroll = 0
		default:
			// other keys: ignore (keep help open so the user can scroll
			// without closing accidentally). `?` or esc/q to exit.
		}
		return m, nil
	}

	// 2. Input mode (substring filter)
	if m.inputMode == InputModeFilter {
		return m.handleFilterInput(msg, key)
	}

	// 3. Global commands
	switch key {
	case "q", "ctrl+c":
		return m, tea.Quit

	case "p", " ":
		m.Paused = !m.Paused

	case "f1", "1":
		m.ActiveTab = TabOverview
	case "f2", "2":
		m.ActiveTab = TabSyscalls
	case "f3", "3":
		m.ActiveTab = TabNetwork
	case "f4", "4":
		m.ActiveTab = TabThreads
	case "f5", "5":
		m.ActiveTab = TabIO
	case "f6", "6":
		m.ActiveTab = TabFD
	case "f7", "7":
		m.ActiveTab = TabTimeline

	case "tab", "right", "l":
		m.ActiveTab = (m.ActiveTab + 1) % TabCount
	case "shift+tab", "left", "h":
		m.ActiveTab = (m.ActiveTab - 1 + TabCount) % TabCount

	case "?":
		m.showHelp = true
		return m, nil

	case "esc":
		// Esc outside input/help clears the active filter (if any)
		if m.filter != "" {
			m.filter = ""
		}
		return m, nil

	case "/":
		// In F6, if the substring filter is empty, first `/` cycles types
		// (legacy behavior for quick ergonomics). When a filter is active
		// or in other views, opens input mode.
		if m.ActiveTab == TabFD && m.filter == "" {
			for i, f := range fdFilters {
				if f == m.FDFilter {
					m.FDFilter = fdFilters[(i+1)%len(fdFilters)]
					return m, nil
				}
			}
			m.FDFilter = fdFilters[0]
			return m, nil
		}
		// Enters input mode with the current value pre-filled
		m.inputMode = InputModeFilter
		m.inputBuf = m.filter
		return m, nil

	case "s":
		path, err := SaveSnapshot(m)
		if err != nil {
			m.toast = fmtToast("⚠ snapshot: %v", err)
		} else {
			m.toast = fmtToast("✓ snapshot: %s", path)
		}
		return m, clearToastAfter(toastTTL)

	case "e":
		if m.exportFile != nil {
			_ = m.exportFile.Close()
			m.exportFile = nil
			m.toast = "✓ export: OFF"
			return m, clearToastAfter(toastTTL)
		}
		f, err := openExportFile()
		if err != nil {
			m.toast = fmtToast("⚠ export: %v", err)
			return m, clearToastAfter(toastTTL)
		}
		m.exportFile = f
		m.toast = fmtToast("✓ export: %s", f.Name())
		return m, tea.Batch(exportTick(), clearToastAfter(toastTTL))
	}
	return m, nil
}

// handleFilterInput processes keys in input mode. Enter confirms, Esc
// cancels keeping the previous filter, Backspace deletes, printable runes
// are concatenated.
func (m Model) handleFilterInput(msg tea.KeyMsg, key string) (Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter:
		m.filter = m.inputBuf
		m.inputMode = InputModeNone
		m.inputBuf = ""
		return m, nil

	case tea.KeyEsc, tea.KeyCtrlC:
		// Cancel: closes input without changing the current filter
		m.inputMode = InputModeNone
		m.inputBuf = ""
		return m, nil

	case tea.KeyBackspace:
		if len(m.inputBuf) > 0 {
			r := []rune(m.inputBuf)
			m.inputBuf = string(r[:len(r)-1])
		}
		return m, nil

	case tea.KeyCtrlU:
		m.inputBuf = ""
		return m, nil

	case tea.KeyRunes:
		// Concatenate event runes — usually 1 rune per keystroke,
		// but paste can deliver several at once
		m.inputBuf += string(msg.Runes)
		return m, nil

	case tea.KeySpace:
		m.inputBuf += " "
		return m, nil
	}

	// Fallback: some terminals deliver printables as a single string
	if len(key) == 1 && unicode.IsPrint(rune(key[0])) {
		m.inputBuf += key
	}
	return m, nil
}

// fmtToast wrapper for fmt.Sprintf — keeps the switch above readable.
func fmtToast(format string, args ...interface{}) string {
	return fmt.Sprintf(format, args...)
}
