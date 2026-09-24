package tui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trentas/ptop/pkg/collector"
)

func TestBuildSnapshot_includesAllFields(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.Width = 120
	m.Height = 40

	snap := buildSnapshot(m)

	if snap.Version != snapshotSchemaVersion {
		t.Errorf("version=%d, expected %d", snap.Version, snapshotSchemaVersion)
	}
	if snap.PID != 1 {
		t.Errorf("PID=%d", snap.PID)
	}
	if snap.Process == "" {
		t.Error("Process empty")
	}
	// Issue criterion: must include CPU, syscalls, FDs, threads, mem, IO, timeline
	if len(snap.Data.CPUHistory) == 0 {
		t.Error("CPUHistory empty")
	}
	if len(snap.Data.SyscallCounts) == 0 {
		t.Error("SyscallCounts empty")
	}
	if len(snap.Data.FDs) == 0 {
		t.Error("FDs empty")
	}
	if len(snap.Data.Threads) == 0 {
		t.Error("Threads empty")
	}
	if snap.Data.MemStats.RSSBytes == 0 {
		t.Error("MemStats.RSSBytes zero")
	}
}

func TestSaveSnapshot_roundtrip(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.Width = 120
	m.Height = 40

	// SaveSnapshot creates in the cwd; isolate via TempDir
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
	// ABSOLUTE, and it has to be: the caller shows this to someone looking at a
	// full-screen TUI, with no shell in sight to say what the working directory
	// was.
	if !filepath.IsAbs(path) {
		t.Errorf("path is not absolute: %s", path)
	}
	if base := filepath.Base(path); !strings.HasPrefix(base, "ptop-snapshot-") {
		t.Errorf("unexpected name: %s", base)
	}
	data, err := os.ReadFile(path)
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
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	for i, line := range lines {
		var s Snapshot
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i, err)
		}
	}
}

// Both axes reached the panels before they reached this file, so an export
// looked complete while carrying everything except them.
func TestSnapshotCarriesTheCPUAndNetworkAxes(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.CPUSites.add(collector.CPUProfile{
		Sites:        []collector.CPUSite{{Func: "main.hot", Module: "app", Samples: 300}},
		TotalSamples: 400, UnresolvedSamples: 100, WindowMs: 1000,
		SampleRateHz: 97, RequestedRateHz: 99, TotalSites: 12, OmittedSamples: 40,
	})
	m.NetThroughput = collector.NetThroughputSample{TxBytes: 5000, RxBytes: 9000, TxBytesPerS: 100}

	d := buildSnapshot(m).Data
	if len(d.CPUSites.Sites) != 1 || d.CPUSites.Sites[0].Func != "main.hot" {
		t.Errorf("cpu sites missing from the export: %+v", d.CPUSites)
	}
	// The readings that make a share refusable have to travel with it.
	if d.CPUSites.TotalSamples != 400 || d.CPUSites.UnresolvedSamples != 100 {
		t.Errorf("sample counts missing: %+v", d.CPUSites)
	}
	if d.CPUSites.SampleRateHz != 97 || d.CPUSites.RequestedRateHz != 99 {
		t.Errorf("achieved/requested rate missing: %+v", d.CPUSites)
	}
	if d.CPUSites.TotalSites != 12 || d.CPUSites.OmittedSamples != 40 {
		t.Errorf("the top-N cut is unreadable without these: %+v", d.CPUSites)
	}
	if d.NetThroughput.TxBytes != 5000 || d.NetThroughput.RxBytes != 9000 {
		t.Errorf("network totals missing: %+v", d.NetThroughput)
	}
}

// One object with two naming conventions is worse than a file that is
// consistently ugly. The wrapper's own fields carry snake_case tags, so the
// types inside it must too — CPUSite and NetThroughputSample were new enough to
// still be taggable without changing a shape anyone had read.
func TestSnapshotAxesUseTheFilesNamingConvention(t *testing.T) {
	m := NewModel(Config{PID: 1, FPS: 5, NoEBPF: true})
	m.CPUSites.add(collector.CPUProfile{
		Sites:        []collector.CPUSite{{Func: "main.hot", Samples: 3}},
		TotalSamples: 3, WindowMs: 1000,
	})
	m.NetThroughput = collector.NetThroughputSample{TxBytes: 1}

	b, err := json.Marshal(buildSnapshot(m))
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	for _, want := range []string{
		`"share_pct"`, `"stack_id"`, `"addr_hex"`, `"samples"`,
		`"tx_bytes"`, `"rx_bytes_per_s"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s — the axis serialized with Go field names", want)
		}
	}
	for _, unwanted := range []string{`"SharePct"`, `"StackID"`, `"AddrHex"`, `"TxBytesPerS"`} {
		if strings.Contains(out, unwanted) {
			t.Errorf("%s leaked a Go field name into the export", unwanted)
		}
	}
}
