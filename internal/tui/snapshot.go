package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/trentas/ptop/pkg/collector"
)

// snapshotSchemaVersion matches semver in the JSON format. Bumping requires
// migration in the consumer; fields added in backward-compat don't bump it.
const snapshotSchemaVersion = 1

// Snapshot is the canonical export format — used both by `s` (one-shot)
// and by `e` (continuous JSONL). Model data only, no UI state.
//
// ─── Every line is self-contained, and it is not free ───────────────────────
//
// A snapshot carries the full rolling history of each trend — CPU, the two I/O
// directions, the two network directions, the fd count — which is historyLen
// (240) points each. The continuous export writes one of these per tick, so
// consecutive lines repeat 239 of every 240 values and a line runs about 40KB:
// roughly 40KB/s while `e` is on.
//
// That is a deliberate trade and not an oversight. It is what makes ONE line of
// the JSONL, or one `s` file, answer a question on its own — no replaying from
// the start of the capture to reconstruct a trend, and no dependency between
// lines when a consumer starts reading in the middle or the writer was paused.
// The alternative, emitting only what changed, buys back the redundancy and
// costs exactly that property.
//
// The size moved when historyLen went from 60 to 240 (the braille sparkline
// carries two samples per cell now, so a wide panel needs four times the
// series). If it ever needs capping, cap what the EXPORT carries rather than
// what the panel keeps — the two serve different readers.
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
	CPUHistory     []float64                      `json:"cpu_history"`
	SyscallCounts  map[string]uint64              `json:"syscall_counts"`
	NetConns       []collector.NetConn            `json:"network_connections"`
	NetErrors      []collector.NetError           `json:"network_errors"`
	MemStats       collector.MemStats             `json:"memory"`
	HeapStats      collector.HeapStats            `json:"heap"`
	Threads        []collector.ThreadInfo         `json:"threads"`
	IOStats        collector.IOStats              `json:"io"`
	FSEvents       []collector.FSEvent            `json:"fs_events"`
	IOReadHist     []float64                      `json:"io_read_history"`
	IOWriteHist    []float64                      `json:"io_write_history"`
	FDs            []collector.FDEntry            `json:"fds"`
	FDCountHistory []float64                      `json:"fd_count_history"`
	FDEvents       []collector.FDEvent            `json:"fd_events"`
	Timeline       []collector.TimelineEvent      `json:"timeline"`
	Signals        []collector.SignalEvent        `json:"signals"`
	TLSPayloads    []collector.TLSPayload         `json:"tls_payloads,omitempty"`
	ProcContext    collector.ProcContext          `json:"proc_context"`
	ProcEvents     []collector.ProcLifecycleEvent `json:"proc_lifecycle"`
	SecurityEvents []collector.SecurityEvent      `json:"security_events"`

	// CPU attribution (#125) and network volume (#128). Added after the fact:
	// both axes reached the panels before they reached this file, so an export
	// looked complete while carrying everything EXCEPT them.
	CPUSites      CPUAttribution                `json:"cpu_sites"`
	NetThroughput collector.NetThroughputSample `json:"net_throughput"`
	NetTxHist     []float64                     `json:"net_tx_history"`
	NetRxHist     []float64                     `json:"net_rx_history"`
}

// CPUAttribution is the folded CPU sampling window as the snapshot carries it:
// which functions the target was caught running in, over how many samples.
//
// Sites alone would not be readable. TotalSamples is what lets a reader refuse
// a share drawn from a dozen samples, SampleRateHz says what the kernel
// actually delivered against RequestedRateHz, UnresolvedSamples is the fraction
// the axis could not name, and TotalSites against len(Sites) says whether the
// list is a census. See collector.CPUProfile for why each one is load-bearing.
type CPUAttribution struct {
	Sites             []collector.CPUSite `json:"sites"`
	TotalSamples      uint64              `json:"total_samples"`
	UnresolvedSamples uint64              `json:"unresolved_samples"`
	WindowMs          uint64              `json:"window_ms"`
	SampleRateHz      float64             `json:"sample_rate_hz"`
	RequestedRateHz   float64             `json:"requested_rate_hz"`
	TotalSites        uint32              `json:"total_sites"`
	OmittedSamples    uint64              `json:"omitted_samples"`
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
			NetErrors:      append([]collector.NetError(nil), m.NetErrors...),
			MemStats:       m.MemStats,
			HeapStats:      m.HeapStats,
			Threads:        append([]collector.ThreadInfo(nil), m.Threads...),
			IOStats:        m.IOStats,
			FSEvents:       append([]collector.FSEvent(nil), m.FSEvents...),
			IOReadHist:     append([]float64(nil), m.IOReadHist...),
			IOWriteHist:    append([]float64(nil), m.IOWriteHist...),
			FDs:            append([]collector.FDEntry(nil), m.FDs...),
			FDCountHistory: append([]float64(nil), m.FDCountHistory...),
			FDEvents:       append([]collector.FDEvent(nil), m.FDEvents...),
			Timeline:       append([]collector.TimelineEvent(nil), m.Timeline...),
			Signals:        append([]collector.SignalEvent(nil), m.Signals...),
			TLSPayloads:    append([]collector.TLSPayload(nil), m.TLSPayloads...),
			ProcContext:    m.ProcCtx,
			ProcEvents:     append([]collector.ProcLifecycleEvent(nil), m.ProcEvents...),
			SecurityEvents: append([]collector.SecurityEvent(nil), m.SecurityEvents...),
			CPUSites:       cpuAttributionOf(m.CPUSites.fold()),
			NetThroughput:  m.NetThroughput,
			NetTxHist:      append([]float64(nil), m.NetTxHist...),
			NetRxHist:      append([]float64(nil), m.NetRxHist...),
		},
	}
}

// SaveSnapshot serializes a snapshot as formatted JSON to a file
// ptop-snapshot-<timestamp>.json in the cwd. Returns the ABSOLUTE path, since
// the caller reports it to someone who cannot see the working directory.
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
	return AbsPath(path), nil
}

// AbsPath resolves a path for DISPLAY, falling back to what it was handed.
//
// Every file ptop writes is named relative to the working directory, so it
// lands wherever the operator launched from. Reporting it back the same way is
// the one place that does not work: the TUI owns the whole screen, so by the
// time someone reads "✓ snapshot: ptop-snapshot-20260924-031500.json" they
// cannot see the shell that would tell them which directory that is. Under
// --serve the same name is written by a process whose working directory is
// usually / and never the reader's.
//
// A failure here is not worth reporting — the file was already written — so the
// relative name is returned rather than an error nobody can act on.
func AbsPath(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
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

// cpuAttributionOf projects the panel's folded window onto the export shape.
func cpuAttributionOf(s cpuSiteSummary) CPUAttribution {
	return CPUAttribution{
		Sites:             append([]collector.CPUSite(nil), s.Sites...),
		TotalSamples:      s.Total,
		UnresolvedSamples: s.Unresolved,
		WindowMs:          s.WindowMs,
		SampleRateHz:      s.RateHz,
		RequestedRateHz:   s.Requested,
		TotalSites:        s.TotalSites,
		OmittedSamples:    s.Omitted,
	}
}
