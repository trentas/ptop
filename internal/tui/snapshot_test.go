package tui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildSnapshot_includesAllFields(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.Width = 120
	m.Height = 40

	snap := buildSnapshot(m)

	if snap.Version != snapshotSchemaVersion {
		t.Errorf("version=%d, esperado %d", snap.Version, snapshotSchemaVersion)
	}
	if snap.PID != 1 {
		t.Errorf("PID=%d", snap.PID)
	}
	if snap.Process == "" {
		t.Error("Process vazio")
	}
	// Critério da issue: deve incluir CPU, syscalls, FDs, threads, mem, IO, timeline
	if len(snap.Data.CPUHistory) == 0 {
		t.Error("CPUHistory vazio")
	}
	if len(snap.Data.SyscallCounts) == 0 {
		t.Error("SyscallCounts vazio")
	}
	if len(snap.Data.FDs) == 0 {
		t.Error("FDs vazio")
	}
	if len(snap.Data.Threads) == 0 {
		t.Error("Threads vazio")
	}
	if snap.Data.MemStats.RSSBytes == 0 {
		t.Error("MemStats.RSSBytes zerado")
	}
}

func TestSaveSnapshot_roundtrip(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.Width = 120
	m.Height = 40

	// SaveSnapshot cria no cwd; isolamos via TempDir
	dir := t.TempDir()
	wd, _ := os.Getwd()
	defer os.Chdir(wd) //nolint:errcheck
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	path, err := SaveSnapshot(m)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if !strings.HasPrefix(path, "xray-snapshot-") {
		t.Errorf("path inesperado: %s", path)
	}
	full := filepath.Join(dir, path)
	data, err := os.ReadFile(full)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var roundtrip Snapshot
	if err := json.Unmarshal(data, &roundtrip); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if roundtrip.Version != snapshotSchemaVersion {
		t.Errorf("version round-trip=%d", roundtrip.Version)
	}
	if len(roundtrip.Data.FDs) != len(m.FDs) {
		t.Errorf("FDs round-trip: %d vs %d", len(roundtrip.Data.FDs), len(m.FDs))
	}
}

func TestExportFile_jsonlLine(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.Width = 120
	m.Height = 40

	dir := t.TempDir()
	wd, _ := os.Getwd()
	defer os.Chdir(wd) //nolint:errcheck
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	f, err := openExportFile()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	if err := writeSnapshotLine(f, m); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := writeSnapshotLine(f, m); err != nil {
		t.Fatalf("write 2: %v", err)
	}

	data, _ := os.ReadFile(f.Name())
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("esperava 2 linhas, got %d", len(lines))
	}
	for i, line := range lines {
		var s Snapshot
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			t.Errorf("linha %d não é JSON válido: %v", i, err)
		}
	}
}
