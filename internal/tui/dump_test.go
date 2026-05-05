package tui

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestDumpFrames opcionalmente dumpa o resultado de View() de cada aba
// num arquivo para inspeção visual. Ative com TUI_DUMP=1.
func TestDumpFrames(t *testing.T) {
	if os.Getenv("TUI_DUMP") == "" {
		t.Skip("set TUI_DUMP=1 para gerar /tmp/tui_*.txt")
	}
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	w, h := 180, 50
	if v := os.Getenv("TUI_W"); v != "" {
		fmt.Sscanf(v, "%d", &w)
	}
	if v := os.Getenv("TUI_H"); v != "" {
		fmt.Sscanf(v, "%d", &h)
	}
	m.Width = w
	m.Height = h
	for tab := 0; tab < TabCount; tab++ {
		m.ActiveTab = tab
		out := m.View()
		safe := strings.ReplaceAll(tabNames[tab], "/", "-")
		safe = strings.ReplaceAll(safe, " ", "_")
		path := "/tmp/tui_" + safe + ".txt"
		if err := os.WriteFile(path, []byte(out), 0644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		t.Logf("dumped %s (%d bytes)", path, len(out))
	}
}
