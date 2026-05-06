package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/trentas/ptop/internal/collector"
)

// snapshotSchemaVersion matches semver in the JSON format. Bumping requires
// migration in the consumer; fields added in backward-compat don't bump it.
const snapshotSchemaVersion = 1

// Snapshot is the canonical export format — used both by `s` (one-shot)
// and by `e` (continuous JSONL). Model data only, no UI state.
type Snapshot struct {
	Version    int          `json:"version"`
	CapturedAt time.Time    `json:"captured_at"`
	PID        int          `json:"pid"`
	Process    string       `json:"process"`
	UptimeMs   int64        `json:"uptime_ms"`
	Data       SnapshotData `json:"data"`
}

// SnapshotData is all the captured telemetry — only fields with a real or
// simulated source that reflect data to be analyzed offline.
type SnapshotData struct {
	CPUHistory     []float64                 `json:"cpu_history"`
	SyscallCounts  map[string]uint64         `json:"syscall_counts"`
	NetConns       []collector.NetConn       `json:"network_connections"`
	MemStats       collector.MemStats        `json:"memory"`
	Threads        []collector.ThreadInfo    `json:"threads"`
	IOStats        collector.IOStats         `json:"io"`
	IOReadHist     []float64                 `json:"io_read_history"`
	IOWriteHist    []float64                 `json:"io_write_history"`
	FDs            []collector.FDEntry       `json:"fds"`
	FDCountHistory []float64                 `json:"fd_count_history"`
	FDEvents       []collector.FDEvent       `json:"fd_events"`
	Timeline       []collector.TimelineEvent `json:"timeline"`
}

// buildSnapshot extracts a Snapshot from the current model state.
func buildSnapshot(m Model) Snapshot {
	return Snapshot{
		Version:    snapshotSchemaVersion,
		CapturedAt: time.Now(),
		PID:        m.cfg.PID,
		Process:    m.ProcessName,
		UptimeMs:   time.Since(m.StartedAt).Milliseconds(),
		Data: SnapshotData{
			CPUHistory:     append([]float64(nil), m.CPUHistory...),
			SyscallCounts:  copyUintMap(m.SyscallCounts),
			NetConns:       append([]collector.NetConn(nil), m.NetConns...),
			MemStats:       m.MemStats,
			Threads:        append([]collector.ThreadInfo(nil), m.Threads...),
			IOStats:        m.IOStats,
			IOReadHist:     append([]float64(nil), m.IOReadHist...),
			IOWriteHist:    append([]float64(nil), m.IOWriteHist...),
			FDs:            append([]collector.FDEntry(nil), m.FDs...),
			FDCountHistory: append([]float64(nil), m.FDCountHistory...),
			FDEvents:       append([]collector.FDEvent(nil), m.FDEvents...),
			Timeline:       append([]collector.TimelineEvent(nil), m.Timeline...),
		},
	}
}

// SaveSnapshot serializes a snapshot as formatted JSON to a file
// ptop-snapshot-<timestamp>.json in the cwd. Returns the created path.
//
// Exposed for main.go to use in the --export-on-quit flow.
func SaveSnapshot(m Model) (string, error) {
	snap := buildSnapshot(m)
	path := fmt.Sprintf("ptop-snapshot-%s.json", snap.CapturedAt.Format("20060102-150405"))
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", err
	}
	return path, nil
}

// openExportFile creates/truncates ptop-export-<timestamp>.jsonl for continuous mode.
func openExportFile() (*os.File, error) {
	path := fmt.Sprintf("ptop-export-%s.jsonl", time.Now().Format("20060102-150405"))
	return os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
}

// writeSnapshotLine writes a JSONL line (serialized snapshot + \n).
// Uses Marshal (not Indent) to save space — JSONL expects one line per entry.
func writeSnapshotLine(f *os.File, m Model) error {
	if f == nil {
		return nil
	}
	snap := buildSnapshot(m)
	data, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}

func copyUintMap(in map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
