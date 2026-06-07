package tui

import (
	"debug/buildinfo"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/trentas/ptop/pkg/collector"
)

// simInterval defines the granularity of the simulation. TickMsg fires at FPS
// (5/s by default) to keep the clock fluid, but the sim only advances when
// this interval elapses. 700ms is the sweet-spot from the React mockup and
// produces visible changes without the "everything jumping" effect.
const simInterval = 700 * time.Millisecond

// topRefreshInterval defines when the top-syscalls/top-files list is
// reordered. Between refreshes, same rows with updated counts — avoids
// visual churn every tick.
const topRefreshInterval = 4 * time.Second

// ─── Tabs ────────────────────────────────────────────────────────────────────

const (
	TabOverview = iota
	TabSyscalls
	TabNetwork
	TabThreads
	TabIO
	TabFD
	TabTimeline
	TabCount
)

// InputMode describes which modal input is active (if any).
type InputMode int

const (
	InputModeNone InputMode = iota
	InputModeFilter
)

var tabNames = []string{
	"F1 Overview",
	"F2 Syscalls",
	"F3 Network",
	"F4 Threads",
	"F5 I/O",
	"F6 FD",
	"F7 Timeline",
}

// ─── Config ──────────────────────────────────────────────────────────────────

// Config comes from main via CLI flags.
type Config struct {
	PID    int
	FPS    int
	NoEBPF bool
	Export bool
}

// ─── Bubbletea messages ──────────────────────────────────────────────────────

type TickMsg time.Time
type FDMsg []collector.FDEntry
type CpuMsg collector.CpuSample
type ThreadsMsg []collector.ThreadInfo
type MemMsg collector.MemStats
type HeapMsg collector.HeapStats
type IOWaitMsg collector.IOWaitSample
type IOThroughputMsg collector.IOThroughputSample
type TimelineMsg collector.TimelineEvent
type FDEventMsg collector.FDEvent
type SyscallsMsg map[string]uint64
type IOEBPFMsg collector.IOEBPFSnapshot
type NetMsg []collector.NetConn
type LockGraphMsg []collector.LockEntry
type LockTimelineMsg collector.TimelineEvent

// exportTickMsg fires periodically when continuous export is ON.
type exportTickMsg time.Time

// clearToastMsg clears the temporary toast/status from the statusbar after N seconds.
type clearToastMsg struct{}

// ─── Model ───────────────────────────────────────────────────────────────────

type Model struct {
	cfg Config

	// Identification
	ProcessName string
	Runtime     string
	State       string
	StartedAt   time.Time

	// Collected data
	CPUHistory     []float64
	SyscallCounts  map[string]uint64
	NetConns       []collector.NetConn
	MemStats       collector.MemStats
	HeapStats      collector.HeapStats // eBPF malloc/free pairing (#53); empty without eBPF
	HeapLiveHist   []float64           // live-heap bytes history for the F1 sparkline
	Threads        []collector.ThreadInfo
	IOStats        collector.IOStats
	IOReadHist     []float64
	IOWriteHist    []float64
	FDs            []collector.FDEntry
	FDCountHistory []float64
	FDEvents       []collector.FDEvent
	Timeline       []collector.TimelineEvent
	LockGraph      []collector.LockEntry

	// UI state
	ActiveTab int
	FDFilter  string
	Paused    bool
	Width     int
	Height    int

	// Toast: temporary message in the statusbar (e.g. "snapshot saved to /tmp/xxx").
	// Empty when no toast is active. clearToastMsg clears it after 2s.
	toast string

	// Continuous export ('e' key or --export flag):
	// when exportFile != nil, exportTickMsg schedules the next JSONL write.
	exportFile *os.File

	// Filter: substring applied to view lists (FD/threads/syscalls).
	// inputMode is InputModeFilter while the user is typing — inputBuf
	// is what's being composed. On Enter, becomes filter; on Esc, discarded.
	filter    string
	inputMode InputMode
	inputBuf  string

	// showHelp: when true, View() renders an overlay with keybindings over
	// the content. Closed by `?`, `esc` or `q`. Arrows/PgUp/PgDn scroll
	// when the overlay doesn't fit in the available height.
	showHelp   bool
	helpScroll int

	// Collectors: the source-priority selection + lifecycle lives in
	// collector.Set, shared with the headless gRPC server (#51). Never nil
	// after NewModel — an empty Set (PID <= 0) leaves every Mock* true.
	collectors *collector.Set

	// Simulation
	rng                *rand.Rand
	tickN              int
	usingMockFDs       bool
	usingMockCPU       bool
	usingMockThreads   bool
	usingMockMem       bool
	usingMockIOWait    bool
	usingMockIOThrough bool
	usingMockSyscalls  bool
	usingMockIOFiles   bool
	usingMockNet       bool
	lastSimAt          time.Time

	// Sources: indicate where the real data came from ("eBPF" | "/proc" | "" for mock).
	// Shown in the help overlay (?) for debugging and visibility.
	cpuSource      string
	syscallsSource string
	ioFilesSource  string
	netSource      string
	threadsSource  string
	memSource      string
	heapSource     string
	locksSource    string

	// Stable caches to avoid visual reordering between ticks.
	// topSyscallNames is recomputed every `topRefreshInterval`; between refreshes
	// we render the same list (alphabetically sorted) with updated counts.
	topSyscallNames []string
	topFilesPaths   []string
	lastTopRefresh  time.Time

	// IO maxima with slow decay — avoids rescaling sparklines every tick.
	ioMaxRead  float64
	ioMaxWrite float64
}

// ─── Construction ────────────────────────────────────────────────────────────

func NewModel(cfg Config) Model {
	m := Model{
		cfg:         cfg,
		ProcessName: detectProcessName(cfg.PID),
		// Runtime is the inspected process's language/runtime badge, best-effort
		// detected from the executable (Go build info / interpreter basename).
		// Empty when unknown — the header omits the badge rather than guess.
		Runtime:       detectRuntime(cfg.PID),
		State:         "RUNNING",
		StartedAt:     time.Now(),
		ActiveTab:     TabOverview,
		FDFilter:      "all",
		SyscallCounts: make(map[string]uint64),
		rng:           rand.New(rand.NewSource(time.Now().UnixNano())),
	}

	m.seedMockData()

	// Source-priority selection + collector lifecycle live in collector.Set,
	// shared with the headless gRPC server (#51) so the wiring isn't
	// duplicated. PID <= 0 yields an empty Set: every Mock* stays true and the
	// model simulates everything. eBPF start failures are logged to stderr by
	// the Set (before the alt-screen) and fall back to /proc where possible.
	m.collectors = collector.NewSet(collector.SetConfig{PID: cfg.PID, NoEBPF: cfg.NoEBPF})

	// Mirror the Set's source labels + mock state into the model fields the
	// help overlay (?) reads. Source "" means no real source started → mock.
	m.cpuSource = m.collectors.Sources.CPU
	m.threadsSource = m.collectors.Sources.Threads
	m.memSource = m.collectors.Sources.Mem
	m.heapSource = m.collectors.Sources.Heap
	m.syscallsSource = m.collectors.Sources.Syscalls
	m.ioFilesSource = m.collectors.Sources.IOFiles
	m.netSource = m.collectors.Sources.Net
	m.locksSource = m.collectors.Sources.Locks

	m.usingMockFDs = m.collectors.MockFDs()
	m.usingMockCPU = m.collectors.MockCPU()
	m.usingMockThreads = m.collectors.MockThreads()
	m.usingMockMem = m.collectors.MockMem()
	m.usingMockIOWait = m.collectors.MockIOWait()
	m.usingMockIOThrough = m.collectors.MockIOThroughput()
	m.usingMockSyscalls = m.collectors.MockSyscalls()
	m.usingMockIOFiles = m.collectors.MockIOFiles()
	m.usingMockNet = m.collectors.MockNet()

	// --export: open the JSONL file right away. If it fails, just warn
	// (doesn't block launch — user can still use the TUI normally).
	if cfg.Export {
		if f, err := openExportFile(); err == nil {
			m.exportFile = f
			m.toast = fmt.Sprintf("✓ export: %s", f.Name())
		} else {
			fmt.Fprintf(os.Stderr, "warning: --export failed: %v\n", err)
		}
	}

	return m
}

// ─── Init / Update / View ────────────────────────────────────────────────────

func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{tick(m.cfg.FPS)}
	if m.collectors.FD != nil {
		cmds = append(cmds, waitForFD(m.collectors.FD))
	}
	if m.collectors.CPUProc != nil {
		cmds = append(cmds, waitForCPU(m.collectors.CPUProc))
	}
	if m.collectors.CPUEBPF != nil {
		cmds = append(cmds, waitForCPUEBPF(m.collectors.CPUEBPF))
	}
	if m.collectors.ThreadsProc != nil {
		cmds = append(cmds, waitForThreads(m.collectors.ThreadsProc))
	}
	if m.collectors.MemProc != nil {
		cmds = append(cmds, waitForMem(m.collectors.MemProc))
	}
	if m.collectors.IOWait != nil {
		cmds = append(cmds, waitForIOWait(m.collectors.IOWait))
	}
	if m.collectors.IOThroughput != nil {
		cmds = append(cmds, waitForIOThroughput(m.collectors.IOThroughput))
	}
	if m.collectors.SyscallsEBPF != nil {
		cmds = append(cmds, waitForSyscalls(m.collectors.SyscallsEBPF))
	}
	if m.collectors.IOEBPF != nil {
		cmds = append(cmds, waitForIOEBPF(m.collectors.IOEBPF))
	}
	if m.collectors.NetworkEBPF != nil {
		cmds = append(cmds, waitForNetEBPF(m.collectors.NetworkEBPF))
	}
	if m.collectors.ThreadsEBPF != nil {
		cmds = append(cmds, waitForThreadsEBPF(m.collectors.ThreadsEBPF))
	}
	if m.collectors.MemEBPF != nil {
		cmds = append(cmds, waitForMemEBPF(m.collectors.MemEBPF))
	}
	if m.collectors.HeapEBPF != nil {
		cmds = append(cmds, waitForHeapEBPF(m.collectors.HeapEBPF))
	}
	if m.collectors.FutexEBPF != nil {
		cmds = append(cmds, waitForFutexEBPF(m.collectors.FutexEBPF))
	}
	if m.exportFile != nil {
		cmds = append(cmds, exportTick())
	}
	if m.toast != "" {
		cmds = append(cmds, clearToastAfter(toastTTL))
	}
	return tea.Batch(cmds...)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch v := msg.(type) {

	case tea.WindowSizeMsg:
		m.Width = v.Width
		m.Height = v.Height
		return m, nil

	case tea.KeyMsg:
		next, cmd := m.handleKey(v)
		return next, cmd

	case TickMsg:
		// Render at configured FPS (clock/uptime stay smooth), but the simulation
		// only advances every simInterval — avoids the "everything jumping" effect
		// from too many changes per second. When the frame is identical, bubbletea
		// detects an empty diff and doesn't even repaint.
		if !m.Paused && time.Since(m.lastSimAt) >= simInterval {
			m.tick()
			m.lastSimAt = time.Now()
		}
		return m, tick(m.cfg.FPS)

	case FDMsg:
		m.FDs = []collector.FDEntry(v)
		m.usingMockFDs = false
		m.FDCountHistory = appendCapped(m.FDCountHistory, float64(len(m.FDs)), 60)
		return m, waitForFD(m.collectors.FD)

	case TimelineMsg:
		// Timeline is prepended; most recent on top. Cap at 120 (same limit
		// used by the simulation).
		m.Timeline = append([]collector.TimelineEvent{collector.TimelineEvent(v)}, m.Timeline...)
		if len(m.Timeline) > 120 {
			m.Timeline = m.Timeline[:120]
		}
		return m, waitForFD(m.collectors.FD)

	case FDEventMsg:
		m.FDEvents = append([]collector.FDEvent{collector.FDEvent(v)}, m.FDEvents...)
		if len(m.FDEvents) > 60 {
			m.FDEvents = m.FDEvents[:60]
		}
		return m, waitForFD(m.collectors.FD)

	case CpuMsg:
		s := collector.CpuSample(v)
		m.CPUHistory = appendCapped(m.CPUHistory, s.UsagePct, 60)
		m.usingMockCPU = false
		// Reschedule on the active source: eBPF takes priority when available.
		if m.collectors.CPUEBPF != nil {
			return m, waitForCPUEBPF(m.collectors.CPUEBPF)
		}
		return m, waitForCPU(m.collectors.CPUProc)

	case ThreadsMsg:
		m.Threads = []collector.ThreadInfo(v)
		m.usingMockThreads = false
		// ThreadsMsg can come from eBPF or /proc — reschedule on the active source.
		if m.collectors.ThreadsEBPF != nil {
			return m, waitForThreadsEBPF(m.collectors.ThreadsEBPF)
		}
		return m, waitForThreads(m.collectors.ThreadsProc)

	case MemMsg:
		m.MemStats = collector.MemStats(v)
		m.usingMockMem = false
		// Reschedule on the active source.
		if m.collectors.MemEBPF != nil {
			return m, waitForMemEBPF(m.collectors.MemEBPF)
		}
		return m, waitForMem(m.collectors.MemProc)

	case HeapMsg:
		m.HeapStats = collector.HeapStats(v)
		m.HeapLiveHist = appendCapped(m.HeapLiveHist, float64(m.HeapStats.LiveHeapBytes), 60)
		return m, waitForHeapEBPF(m.collectors.HeapEBPF)

	case IOWaitMsg:
		m.IOStats.IOWaitPct = collector.IOWaitSample(v).Pct
		m.usingMockIOWait = false
		return m, waitForIOWait(m.collectors.IOWait)

	case clearToastMsg:
		m.toast = ""
		return m, nil

	case exportTickMsg:
		// Continuous export: writes one JSONL line per tick. If the write fails,
		// closes the file and shows an error toast — doesn't hang the TUI.
		if m.exportFile != nil {
			if err := writeSnapshotLine(m.exportFile, m); err != nil {
				_ = m.exportFile.Close()
				m.exportFile = nil
				m.toast = fmt.Sprintf("⚠ export: %v", err)
				return m, clearToastAfter(toastTTL)
			}
			return m, exportTick()
		}
		return m, nil

	case SyscallsMsg:
		// Full snapshot of the syscall_count map coming from the eBPF tracer.
		// We overwrite the entire counts: the tracer keeps the per-pid cumulative.
		m.SyscallCounts = map[string]uint64(v)
		m.usingMockSyscalls = false
		return m, waitForSyscalls(m.collectors.SyscallsEBPF)

	case NetMsg:
		m.NetConns = []collector.NetConn(v)
		m.usingMockNet = false
		return m, waitForNetEBPF(m.collectors.NetworkEBPF)

	case LockGraphMsg:
		m.LockGraph = []collector.LockEntry(v)
		return m, waitForFutexEBPF(m.collectors.FutexEBPF)

	case LockTimelineMsg:
		ev := collector.TimelineEvent(v)
		m.Timeline = append([]collector.TimelineEvent{ev}, m.Timeline...)
		if len(m.Timeline) > 120 {
			m.Timeline = m.Timeline[:120]
		}
		return m, waitForFutexEBPF(m.collectors.FutexEBPF)

	case IOEBPFMsg:
		s := collector.IOEBPFSnapshot(v)
		m.IOStats.TopFiles = s.TopFiles
		// Buckets now come from the current window (read+write counts of this interval).
		// We merge with existing labels to preserve order.
		if len(s.Buckets) == len(m.IOStats.LatencyBuckets) {
			for i, b := range s.Buckets {
				m.IOStats.LatencyBuckets[i].Read = b.Read
				m.IOStats.LatencyBuckets[i].Write = b.Write
			}
		} else if len(s.Buckets) > 0 {
			m.IOStats.LatencyBuckets = s.Buckets
		}
		m.usingMockIOFiles = false
		return m, waitForIOEBPF(m.collectors.IOEBPF)

	case IOThroughputMsg:
		s := collector.IOThroughputSample(v)
		m.IOStats.ReadBytesPerS = s.ReadBytesPerS
		m.IOStats.WriteBytesPerS = s.WriteBytesPerS
		m.IOStats.ReadOps = s.ReadOps
		m.IOStats.WriteOps = s.WriteOps
		m.IOReadHist = appendCapped(m.IOReadHist, s.ReadBytesPerS, 60)
		m.IOWriteHist = appendCapped(m.IOWriteHist, s.WriteBytesPerS, 60)
		m.ioMaxRead = math.Max(m.ioMaxRead*0.97, s.ReadBytesPerS)
		m.ioMaxWrite = math.Max(m.ioMaxWrite*0.97, s.WriteBytesPerS)
		if m.ioMaxRead < 100*1024 {
			m.ioMaxRead = 100 * 1024
		}
		if m.ioMaxWrite < 100*1024 {
			m.ioMaxWrite = 100 * 1024
		}
		m.usingMockIOThrough = false
		return m, waitForIOThroughput(m.collectors.IOThroughput)
	}
	return m, nil
}

func (m Model) View() string {
	if m.Width == 0 || m.Height == 0 {
		return "starting..."
	}

	header := renderHeader(m)
	tabbar := renderTabBar(m)

	// Statusbar is replaced by the input box when inputMode == filter
	var statusbar string
	if m.inputMode == InputModeFilter {
		statusbar = renderFilterInput(m, m.Width)
	} else {
		statusbar = renderStatusBar(m)
	}

	chromeH := lipgloss.Height(header) + lipgloss.Height(tabbar) + lipgloss.Height(statusbar)
	contentH := m.Height - chromeH
	if contentH < 4 {
		contentH = 4
	}
	contentW := m.Width

	// Help overlay takes priority over the view content
	if m.showHelp {
		overlay := renderHelpOverlayWithStatus(m, contentW, contentH)
		return header + "\n" + tabbar + "\n" + overlay + "\n" + statusbar
	}

	var content string
	switch m.ActiveTab {
	case TabSyscalls:
		content = renderSyscallsView(m, contentW, contentH)
	case TabNetwork:
		content = renderNetworkView(m, contentW, contentH)
	case TabThreads:
		content = renderThreadsView(m, contentW, contentH)
	case TabIO:
		content = renderIOView(m, contentW, contentH)
	case TabFD:
		content = renderFDView(m, contentW, contentH)
	case TabTimeline:
		content = renderTimelineView(m, contentW, contentH)
	default:
		content = renderOverviewView(m, contentW, contentH)
	}

	// Ensures exact height for the content (lipgloss will truncate if it exceeds)
	contentBox := lipgloss.NewStyle().
		Width(contentW).
		Height(contentH).
		MaxHeight(contentH).
		Background(ColorBG).
		Render(content)

	return header + "\n" + tabbar + "\n" + contentBox + "\n" + statusbar
}

// ─── Simulation ──────────────────────────────────────────────────────────────

var simSyscalls = []string{
	"epoll_wait", "read", "write", "futex", "recvmsg", "sendmsg",
	"openat", "close", "mmap", "munmap", "brk", "nanosleep",
	"stat", "fstat", "poll", "select", "clock_gettime", "getpid",
}

var simTimelineMessages = map[string][]string{
	"syscall": {
		"openat /etc/config.json",
		"read fd=7 (socket)",
		"write fd=1 (stdout)",
		"futex WAIT mutex-A",
	},
	"net": {
		"TCP SYN → 10.0.1.5:5432",
		"recv 4096B from :5432",
		"send 128B to :443",
	},
	"mem": {
		"mmap 4096B ANON",
		"page fault addr=0x7fff…",
		"brk +8192B",
	},
	"cpu": {
		"preempted after 12ms",
		"migrated core 2→5",
		"voluntary yield",
	},
	"lock": {
		"mutex-A acquired thr=1",
		"mutex-A released",
		"RWlock read thr=3",
	},
	"io": {
		"read /data/db/index.db 4096B 0.8ms",
		"write /var/log/app/api.log 512B",
		"fsync /data/db/wal.db-shm 18ms ⚠",
		"stat /proc/self/status ×12 (polling?)",
	},
	"fd": {
		"openat → fd=15 /tmp/tmpXXXX",
		"close fd=11",
		"dup2 fd=4 → fd=16",
		"fcntl fd=6 O_NONBLOCK",
		"read fd=4 2048B (db)",
		"write fd=7 512B (log)",
	},
}

var simCategories = []string{"syscall", "net", "mem", "cpu", "lock", "io", "fd"}

func (m *Model) seedMockData() {
	r := m.rng

	// CPU history
	m.CPUHistory = make([]float64, 60)
	for i := range m.CPUHistory {
		m.CPUHistory[i] = 5 + r.Float64()*30
	}

	// Syscalls
	for _, name := range simSyscalls {
		m.SyscallCounts[name] = uint64(r.Intn(200))
	}

	// Net
	m.NetConns = []collector.NetConn{
		{FD: 4, Type: "TCP", Remote: "10.0.1.5:5432", State: "WAIT", Dir: "→", LatencyMs: 42, TxBytes: 12000, RxBytes: 88000},
		{FD: 3, Type: "TCP", Remote: "10.0.0.1:443", State: "ESTABLISHED", Dir: "↔", LatencyMs: 8, TxBytes: 480000, RxBytes: 500000},
		{FD: 5, Type: "UNIX", Remote: "/var/run/docker.sock", State: "ESTABLISHED", Dir: "→", LatencyMs: 1, TxBytes: 22000, RxBytes: 22000},
	}

	// Memory
	m.MemStats = collector.MemStats{
		RSSBytes:   148 * (1 << 20),
		HeapBytes:  92 * (1 << 20),
		PageFaults: 14,
		AllocsPerS: 320,
	}

	// Threads
	m.Threads = []collector.ThreadInfo{
		{TID: 1, Name: "main", State: "running", CPUPct: 34},
		{TID: 2, Name: "worker-1", State: "blocked", Waiting: "mutex-A"},
		{TID: 3, Name: "worker-2", State: "running", CPUPct: 18},
		{TID: 4, Name: "gc", State: "sleeping", Waiting: "nanosleep"},
		{TID: 5, Name: "http-pool", State: "blocked", Waiting: "epoll_wait"},
	}

	// I/O history
	m.IOReadHist = make([]float64, 60)
	m.IOWriteHist = make([]float64, 60)
	for i := range m.IOReadHist {
		m.IOReadHist[i] = r.Float64() * 800 * 1024
		m.IOWriteHist[i] = r.Float64() * 400 * 1024
	}

	// I/O totals + top files + buckets
	m.IOStats = collector.IOStats{
		ReadBytesPerS:  450 * 1024,
		WriteBytesPerS: 220 * 1024,
		ReadOps:        2400,
		WriteOps:       1200,
		Fsyncs:         18,
		Opens:          42,
		IOWaitPct:      4.2,
		TopFiles: []collector.IOFileStats{
			{Path: "/data/db/index.db", Type: "db", Reads: 240, Writes: 120, Bytes: 88120, LatencyMs: 1.2, Fsyncs: 18},
			{Path: "/var/log/app/api.log", Type: "log", Reads: 0, Writes: 380, Bytes: 32100, LatencyMs: 0.3, Fsyncs: 0},
			{Path: "/etc/config/settings.json", Type: "cfg", Reads: 44, Writes: 0, Bytes: 4096, LatencyMs: 0.2, Fsyncs: 0},
			{Path: "/tmp/cache/sessions.bin", Type: "tmp", Reads: 88, Writes: 64, Bytes: 61000, LatencyMs: 0.8, Fsyncs: 2},
			{Path: "/data/db/wal.db-shm", Type: "db", Reads: 120, Writes: 200, Bytes: 20480, LatencyMs: 4.1, Fsyncs: 34},
			{Path: "/proc/self/status", Type: "proc", Reads: 480, Writes: 0, Bytes: 512, LatencyMs: 0.05, Fsyncs: 0},
		},
		LatencyBuckets: []collector.LatencyBucket{
			{Label: "<0.1ms", Read: 42, Write: 28},
			{Label: "0.1-1ms", Read: 31, Write: 19},
			{Label: "1-5ms", Read: 14, Write: 22},
			{Label: "5-20ms", Read: 8, Write: 11},
			{Label: ">20ms", Read: 3, Write: 6},
		},
	}

	// FDs
	m.FDs = []collector.FDEntry{
		{FD: 0, Type: "pipe", Desc: "stdin", Flags: "O_RDONLY", AgeMs: 3820 * 1000},
		{FD: 1, Type: "pipe", Desc: "stdout", Flags: "O_WRONLY", Bytes: 142300, AgeMs: 3820 * 1000, Active: true},
		{FD: 2, Type: "pipe", Desc: "stderr", Flags: "O_WRONLY", Bytes: 1200, AgeMs: 3820 * 1000},
		{FD: 3, Type: "socket", Desc: "TCP 10.0.0.1:443", Flags: "O_RDWR", Bytes: 980400, AgeMs: 3790 * 1000, Active: true},
		{FD: 4, Type: "socket", Desc: "TCP 10.0.1.5:5432", Flags: "O_RDWR", Bytes: 2340100, AgeMs: 3750 * 1000, Active: true},
		{FD: 5, Type: "socket", Desc: "UNIX /var/run/docker.sock", Flags: "O_RDWR", Bytes: 44200, AgeMs: 3700 * 1000},
		{FD: 6, Type: "file", Desc: "/data/db/index.db", Flags: "O_RDWR", Bytes: 8812400, AgeMs: 3650 * 1000, Active: true},
		{FD: 7, Type: "file", Desc: "/var/log/app/api.log", Flags: "O_WRONLY", Bytes: 3210000, AgeMs: 3600 * 1000, Active: true},
		{FD: 8, Type: "file", Desc: "/etc/config/settings.json", Flags: "O_RDONLY", Bytes: 4096, AgeMs: 3400 * 1000},
		{FD: 9, Type: "epoll", Desc: "epoll fd (5 watches)", Flags: "O_RDWR", AgeMs: 3820 * 1000, Active: true},
		{FD: 10, Type: "timer", Desc: "timerfd interval=100ms", Flags: "O_RDONLY", AgeMs: 3500 * 1000, Active: true},
		{FD: 11, Type: "file", Desc: "/tmp/cache/sessions.bin", Flags: "O_RDWR", Bytes: 610000, AgeMs: 1200 * 1000},
		{FD: 12, Type: "socket", Desc: "TCP 10.0.2.1:6379", Flags: "O_RDWR", Bytes: 220000, AgeMs: 800 * 1000, Active: true},
		{FD: 13, Type: "pipe", Desc: "[pipe:anon] worker→main", Flags: "O_RDWR", Bytes: 88200, AgeMs: 600 * 1000},
		{FD: 14, Type: "file", Desc: "/proc/self/status", Flags: "O_RDONLY", Bytes: 512, AgeMs: 12 * 1000},
	}

	// FD count history
	m.FDCountHistory = make([]float64, 60)
	for i := range m.FDCountHistory {
		m.FDCountHistory[i] = float64(len(m.FDs)) + r.Float64()*4 - 2
	}

	// Timeline (seeded empty — gets filled by tick)
	m.Timeline = make([]collector.TimelineEvent, 0, 120)
	m.FDEvents = make([]collector.FDEvent, 0, 60)

	// Initialize stable caches and decaying maxima
	m.refreshTopN()
	m.lastTopRefresh = time.Now()
	m.lastSimAt = time.Now()

	// Estimate initial maxima from the seeded history
	for _, v := range m.IOReadHist {
		if v > m.ioMaxRead {
			m.ioMaxRead = v
		}
	}
	for _, v := range m.IOWriteHist {
		if v > m.ioMaxWrite {
			m.ioMaxWrite = v
		}
	}

	// Pre-populate with a few events so the UI doesn't start empty
	for i := 0; i < 12; i++ {
		m.pushTimeline()
		m.maybePushFDEvent()
	}
}

// refreshTopN recomputes which syscalls/files appear in the top — in
// alphabetical order so that visual position doesn't change between refreshes.
// Counts keep updating every tick; only the set+order is frozen.
func (m *Model) refreshTopN() {
	all := sortedSyscalls(m.SyscallCounts)
	if len(all) > 8 {
		all = all[:8]
	}
	names := make([]string, 0, len(all))
	for _, s := range all {
		names = append(names, s.name)
	}
	sort.Strings(names)
	m.topSyscallNames = names

	files := append([]collector.IOFileStats{}, m.IOStats.TopFiles...)
	sort.Slice(files, func(i, j int) bool {
		return files[i].Reads+files[i].Writes > files[j].Reads+files[j].Writes
	})
	if len(files) > 8 {
		files = files[:8]
	}
	paths := make([]string, 0, len(files))
	for _, f := range files {
		paths = append(paths, f.Path)
	}
	sort.Strings(paths)
	m.topFilesPaths = paths
}

// tick advances the simulation by one step. Called by TickMsg when not paused.
// In real eBPF mode, this function coexists with collector messages:
// fields updated here are overwritten when a real message arrives.
func (m *Model) tick() {
	m.tickN++
	r := m.rng

	// CPU — only simulates if the real collector isn't running.
	// When real, the field is fed via CpuMsg.
	if m.usingMockCPU {
		prev := 20.0
		if len(m.CPUHistory) > 0 {
			prev = m.CPUHistory[len(m.CPUHistory)-1]
		}
		delta := (r.Float64()*2 - 0.9) * 12
		cpu := clamp(prev+delta, 0, 100)
		m.CPUHistory = appendCapped(m.CPUHistory, cpu, 60)
	}

	// Syscalls — only simulates if the eBPF tracer isn't running.
	if m.usingMockSyscalls {
		for i := 0; i < 3; i++ {
			k := simSyscalls[r.Intn(len(simSyscalls))]
			m.SyscallCounts[k] += uint64(r.Intn(20))
		}
	}

	// Memory — only simulates if the real collector isn't running
	if m.usingMockMem {
		if r.Float64() > 0.7 {
			m.MemStats.RSSBytes += uint64(r.Intn(2 << 20))
		}
		m.MemStats.HeapBytes = uint64(clamp(float64(m.MemStats.HeapBytes)+(r.Float64()-0.5)*3*(1<<20), 60*(1<<20), 256*(1<<20)))
		if r.Float64() > 0.8 {
			m.MemStats.PageFaults++
		}
		m.MemStats.AllocsPerS = uint64(clamp(float64(m.MemStats.AllocsPerS)+r.Float64()*8-3, 50, 2000))
	}

	// Network — latency jitter + oscillating state. We only simulate when
	// the eBPF network collector isn't running.
	if m.usingMockNet {
		for i := range m.NetConns {
			c := &m.NetConns[i]
			c.LatencyMs = clamp(c.LatencyMs+(r.Float64()-0.5)*5, 1, 200)
			if i == 0 && r.Float64() > 0.7 {
				if c.State == "WAIT" {
					c.State = "RECV"
				} else {
					c.State = "WAIT"
				}
			}
		}
	}

	// Threads — only simulates if the real collector isn't running
	if m.usingMockThreads {
		states := []string{"running", "blocked", "sleeping"}
		for i := range m.Threads {
			t := &m.Threads[i]
			if t.State == "running" {
				t.CPUPct = clamp(t.CPUPct+(r.Float64()-0.5)*8, 0, 99)
			} else {
				t.CPUPct = 0
			}
			if r.Float64() > 0.95 {
				t.State = states[r.Intn(len(states))]
			}
		}
	}

	// I/O throughput — only simulates if the real collector isn't running
	if m.usingMockIOThrough {
		nr := r.Float64() * 1200 * 1024
		if r.Float64() > 0.85 {
			nr += 2000 * 1024
		}
		nw := r.Float64() * 600 * 1024
		if r.Float64() > 0.9 {
			nw += 1500 * 1024
		}
		m.IOReadHist = appendCapped(m.IOReadHist, nr, 60)
		m.IOWriteHist = appendCapped(m.IOWriteHist, nw, 60)
		m.IOStats.ReadBytesPerS = nr
		m.IOStats.WriteBytesPerS = nw

		// "Decay" maximum: grows at the peak instant and drops 3% per tick.
		// This avoids harsh sparkline rescaling whenever an isolated high value
		// appears and then disappears.
		const decayPerTick = 0.97
		m.ioMaxRead = math.Max(m.ioMaxRead*decayPerTick, nr)
		m.ioMaxWrite = math.Max(m.ioMaxWrite*decayPerTick, nw)
		if m.ioMaxRead < 100*1024 { // visual floor: 100KB/s
			m.ioMaxRead = 100 * 1024
		}
		if m.ioMaxWrite < 100*1024 {
			m.ioMaxWrite = 100 * 1024
		}
		m.IOStats.ReadOps += uint64(r.Intn(12))
		m.IOStats.WriteOps += uint64(r.Intn(6))
	}
	if r.Float64() > 0.8 {
		m.IOStats.Fsyncs++
	}
	if r.Float64() > 0.7 {
		m.IOStats.Opens++
	}
	if m.usingMockIOWait {
		m.IOStats.IOWaitPct = clamp(m.IOStats.IOWaitPct+(r.Float64()-0.5)*2, 0, 40)
	}

	// TopFiles + LatencyBuckets only simulate when the eBPF io collector
	// isn't running — when running, IOEBPFMsg replaces these fields.
	if m.usingMockIOFiles {
		for i := range m.IOStats.TopFiles {
			f := &m.IOStats.TopFiles[i]
			if r.Float64() > 0.4 {
				f.Reads += uint64(r.Intn(8))
			}
			if r.Float64() > 0.6 {
				f.Writes += uint64(r.Intn(4))
			}
			f.Bytes += uint64(r.Intn(512))
			f.LatencyMs = clamp(f.LatencyMs+(r.Float64()-0.5)*0.4, 0.05, 50)
			if f.Type == "db" && r.Float64() > 0.7 {
				f.Fsyncs++
			}
		}
		for i := range m.IOStats.LatencyBuckets {
			b := &m.IOStats.LatencyBuckets[i]
			bias := 1.0
			if i == 0 {
				bias = 2.0
			}
			b.Read = clamp(b.Read+(r.Float64()-0.4)*2*bias, 1, 1000)
			b.Write = clamp(b.Write+(r.Float64()-0.4)*2*bias, 1, 1000)
		}
	}

	// FDs — we only simulate when there's no real collector plugged in
	if m.usingMockFDs {
		m.simulateFDs()
	}

	// Timeline + FD events — pushes 1 each tick (on average)
	if r.Float64() > 0.3 {
		m.pushTimeline()
	}
	if r.Float64() > 0.5 {
		m.maybePushFDEvent()
	}

	// Top-N: reorder rarely to avoid visual reordering every tick
	if time.Since(m.lastTopRefresh) >= topRefreshInterval {
		m.refreshTopN()
		m.lastTopRefresh = time.Now()
	}
}

func (m *Model) simulateFDs() {
	r := m.rng

	// Update age + bytes
	for i := range m.FDs {
		f := &m.FDs[i]
		f.AgeMs += int64(time.Second / time.Duration(maxInt(m.cfg.FPS, 1)) / time.Millisecond)
		if f.Active {
			f.Bytes += uint64(r.Intn(4096))
		}
		if r.Float64() > 0.75 {
			f.Active = !f.Active
		}
	}

	// Occasionally open a new FD
	if r.Float64() > 0.85 && len(m.FDs) < 22 {
		types := []string{"file", "socket", "pipe"}
		descs := []string{
			fmt.Sprintf("/tmp/tmp_%04d", r.Intn(9999)),
			fmt.Sprintf("TCP 10.0.3.%d:8080", r.Intn(255)),
			"[pipe:anon]",
		}
		idx := r.Intn(len(types))
		nextFD := 0
		for _, f := range m.FDs {
			if f.FD > nextFD {
				nextFD = f.FD
			}
		}
		m.FDs = append(m.FDs, collector.FDEntry{
			FD: nextFD + 1, Type: types[idx], Desc: descs[idx],
			Flags: "O_RDWR", AgeMs: 0, Active: true,
		})
	}

	// Occasionally close a disposable FD (fd > 10)
	if r.Float64() > 0.88 && len(m.FDs) > 8 {
		victims := []int{}
		for i, f := range m.FDs {
			if f.FD > 10 {
				victims = append(victims, i)
			}
		}
		if len(victims) > 0 {
			i := victims[r.Intn(len(victims))]
			m.FDs = append(m.FDs[:i], m.FDs[i+1:]...)
		}
	}

	m.FDCountHistory = appendCapped(m.FDCountHistory, float64(len(m.FDs)), 60)
}

func (m *Model) pushTimeline() {
	r := m.rng
	cat := simCategories[r.Intn(len(simCategories))]
	msgs := simTimelineMessages[cat]
	msg := msgs[r.Intn(len(msgs))]
	ev := collector.TimelineEvent{
		Timestamp: time.Now(),
		Category:  cat,
		Message:   msg,
	}
	// prepend (most recent first)
	m.Timeline = append([]collector.TimelineEvent{ev}, m.Timeline...)
	if len(m.Timeline) > 120 {
		m.Timeline = m.Timeline[:120]
	}
}

func (m *Model) maybePushFDEvent() {
	r := m.rng
	templates := []func() string{
		func() string { return fmt.Sprintf("openat fd=%d /tmp/tmp_%04d", r.Intn(20)+3, r.Intn(9999)) },
		func() string { return fmt.Sprintf("close fd=%d", r.Intn(15)+3) },
		func() string {
			return fmt.Sprintf("dup2 fd=%d → fd=%d", r.Intn(8)+3, r.Intn(8)+12)
		},
		func() string { return fmt.Sprintf("read fd=%d %dB", r.Intn(8)+3, r.Intn(4096)) },
		func() string { return fmt.Sprintf("write fd=%d %dB", r.Intn(8)+3, r.Intn(1024)) },
		func() string { return fmt.Sprintf("fcntl fd=%d F_SETFL O_NONBLOCK", r.Intn(8)+3) },
	}
	t := templates[r.Intn(len(templates))]
	m.FDEvents = append([]collector.FDEvent{{Timestamp: time.Now(), Message: t()}}, m.FDEvents...)
	if len(m.FDEvents) > 60 {
		m.FDEvents = m.FDEvents[:60]
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func tick(fps int) tea.Cmd {
	if fps <= 0 {
		fps = 5
	}
	d := time.Second / time.Duration(fps)
	return tea.Tick(d, func(t time.Time) tea.Msg { return TickMsg(t) })
}

// exportInterval defines how frequently continuous export writes a
// JSONL line. simInterval (700ms) would be too noisy — 2s is a
// compromise between granularity and generated file size.
const exportInterval = 2 * time.Second

func exportTick() tea.Cmd {
	return tea.Tick(exportInterval, func(t time.Time) tea.Msg { return exportTickMsg(t) })
}

// toastTTL is how long the temporary statusbar message stays visible.
const toastTTL = 2 * time.Second

func clearToastAfter(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(time.Time) tea.Msg { return clearToastMsg{} })
}

// Close releases resources opened by the model: the export file and the
// collectors (which stops any eBPF tracers so they don't linger after exit).
// main.go calls this after p.Run() returns to ensure flush.
func (m Model) Close() {
	if m.exportFile != nil {
		_ = m.exportFile.Close()
	}
	m.collectors.Stop()
}

// waitForFD blocks until receiving a message from the FD collector and delivers it to Update.
// FDCollector publishes 3 different types on the same channel; we demux via
// type-switch and map to specific tea.Msg.
func waitForFD(c *collector.FDCollector) tea.Cmd {
	if c == nil {
		return nil
	}
	return func() tea.Msg {
		v := <-c.Subscribe()
		switch t := v.(type) {
		case []collector.FDEntry:
			return FDMsg(t)
		case collector.TimelineEvent:
			return TimelineMsg(t)
		case collector.FDEvent:
			return FDEventMsg(t)
		}
		return TickMsg(time.Now())
	}
}

func waitForCPU(c *collector.CPUCollector) tea.Cmd {
	if c == nil {
		return nil
	}
	return func() tea.Msg {
		v := <-c.Subscribe()
		if s, ok := v.(collector.CpuSample); ok {
			return CpuMsg(s)
		}
		return TickMsg(time.Now())
	}
}

func waitForCPUEBPF(c *collector.CPUEBPFCollector) tea.Cmd {
	if c == nil {
		return nil
	}
	return func() tea.Msg {
		ch := c.Subscribe()
		if ch == nil {
			return TickMsg(time.Now())
		}
		v := <-ch
		if s, ok := v.(collector.CpuSample); ok {
			return CpuMsg(s)
		}
		return TickMsg(time.Now())
	}
}

func waitForThreadsEBPF(c *collector.ThreadsEBPFCollector) tea.Cmd {
	if c == nil {
		return nil
	}
	return func() tea.Msg {
		ch := c.Subscribe()
		if ch == nil {
			return TickMsg(time.Now())
		}
		v := <-ch
		if t, ok := v.([]collector.ThreadInfo); ok {
			return ThreadsMsg(t)
		}
		return TickMsg(time.Now())
	}
}

func waitForThreads(c *collector.ThreadsCollector) tea.Cmd {
	if c == nil {
		return nil
	}
	return func() tea.Msg {
		v := <-c.Subscribe()
		if t, ok := v.([]collector.ThreadInfo); ok {
			return ThreadsMsg(t)
		}
		return TickMsg(time.Now())
	}
}

func waitForFutexEBPF(c *collector.FutexEBPFCollector) tea.Cmd {
	if c == nil {
		return nil
	}
	return func() tea.Msg {
		ch := c.Subscribe()
		if ch == nil {
			return TickMsg(time.Now())
		}
		v := <-ch
		switch t := v.(type) {
		case []collector.LockEntry:
			return LockGraphMsg(t)
		case collector.TimelineEvent:
			return LockTimelineMsg(t)
		}
		return TickMsg(time.Now())
	}
}

func waitForMemEBPF(c *collector.MemEBPFCollector) tea.Cmd {
	if c == nil {
		return nil
	}
	return func() tea.Msg {
		ch := c.Subscribe()
		if ch == nil {
			return TickMsg(time.Now())
		}
		v := <-ch
		if s, ok := v.(collector.MemStats); ok {
			return MemMsg(s)
		}
		return TickMsg(time.Now())
	}
}

// waitForHeapEBPF drains the heap collector's channel. It carries two payloads:
// the periodic HeapStats aggregate (what the F1 panel renders) and per-alloc/free
// HeapEvents (for the gRPC stream). The TUI only surfaces the aggregate, so it
// blocks reading — discarding HeapEvents — until the next HeapStats, which avoids
// a per-allocation render storm.
func waitForHeapEBPF(c *collector.HeapEBPFCollector) tea.Cmd {
	if c == nil {
		return nil
	}
	return func() tea.Msg {
		ch := c.Subscribe()
		if ch == nil {
			return TickMsg(time.Now())
		}
		for v := range ch {
			if s, ok := v.(collector.HeapStats); ok {
				return HeapMsg(s)
			}
			// HeapEvent: not shown in the aggregate panel — keep reading.
		}
		return TickMsg(time.Now())
	}
}

func waitForMem(c *collector.MemCollector) tea.Cmd {
	if c == nil {
		return nil
	}
	return func() tea.Msg {
		v := <-c.Subscribe()
		if s, ok := v.(collector.MemStats); ok {
			return MemMsg(s)
		}
		return TickMsg(time.Now())
	}
}

func waitForIOWait(c *collector.IOWaitCollector) tea.Cmd {
	if c == nil {
		return nil
	}
	return func() tea.Msg {
		v := <-c.Subscribe()
		if s, ok := v.(collector.IOWaitSample); ok {
			return IOWaitMsg(s)
		}
		return TickMsg(time.Now())
	}
}

func waitForIOThroughput(c *collector.IOThroughputCollector) tea.Cmd {
	if c == nil {
		return nil
	}
	return func() tea.Msg {
		v := <-c.Subscribe()
		if s, ok := v.(collector.IOThroughputSample); ok {
			return IOThroughputMsg(s)
		}
		return TickMsg(time.Now())
	}
}

func waitForSyscalls(c *collector.SyscallsEBPFCollector) tea.Cmd {
	if c == nil {
		return nil
	}
	return func() tea.Msg {
		ch := c.Subscribe()
		if ch == nil {
			return TickMsg(time.Now())
		}
		v := <-ch
		if m, ok := v.(map[string]uint64); ok {
			return SyscallsMsg(m)
		}
		return TickMsg(time.Now())
	}
}

func waitForNetEBPF(c *collector.NetworkEBPFCollector) tea.Cmd {
	if c == nil {
		return nil
	}
	return func() tea.Msg {
		ch := c.Subscribe()
		if ch == nil {
			return TickMsg(time.Now())
		}
		v := <-ch
		if conns, ok := v.([]collector.NetConn); ok {
			return NetMsg(conns)
		}
		return TickMsg(time.Now())
	}
}

func waitForIOEBPF(c *collector.IOEBPFCollector) tea.Cmd {
	if c == nil {
		return nil
	}
	return func() tea.Msg {
		ch := c.Subscribe()
		if ch == nil {
			return TickMsg(time.Now())
		}
		v := <-ch
		if s, ok := v.(collector.IOEBPFSnapshot); ok {
			return IOEBPFMsg(s)
		}
		return TickMsg(time.Now())
	}
}

func appendCapped(s []float64, v float64, capN int) []float64 {
	s = append(s, v)
	if len(s) > capN {
		s = s[len(s)-capN:]
	}
	return s
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// detectProcessName resolves the short process name (~16 chars). The
// per-OS lookup lives in process_name_{linux,darwin}.go so this stays
// free of build tags. Empty / failure returns "(?)" so the header
// clearly signals "we couldn't identify the process".
func detectProcessName(pid int) string {
	if pid <= 0 {
		return "(?)"
	}
	name := strings.TrimSpace(osProcessName(pid))
	if name == "" {
		return "(?)"
	}
	return name
}

// detectRuntime best-effort identifies the inspected process's language or
// runtime for the header badge. It resolves the executable path (per-OS, via
// osExePath in process_path_{linux,darwin}.go), reads embedded Go build info,
// and otherwise guesses from the binary basename. Returns "" when unknown —
// the header omits the badge rather than ever showing a mock value.
func detectRuntime(pid int) string {
	if pid <= 0 {
		return ""
	}
	exe := osExePath(pid)
	if exe == "" {
		return ""
	}
	if bi, err := buildinfo.ReadFile(exe); err == nil && bi.GoVersion != "" {
		return formatGoVersion(bi.GoVersion)
	}
	return runtimeFromBasename(filepath.Base(exe))
}

// formatGoVersion turns a runtime version string like "go1.22.3" into the
// badge form "Go 1.22" (major.minor — patch is noise in a status badge).
func formatGoVersion(v string) string {
	v = strings.TrimPrefix(v, "go")
	if parts := strings.Split(v, "."); len(parts) >= 2 {
		return "Go " + parts[0] + "." + parts[1]
	}
	return "Go " + v
}

// runtimeFromBasename maps a known interpreter/executable name to a label.
// Unknown names return "" so the badge stays hidden.
func runtimeFromBasename(base string) string {
	switch base = strings.ToLower(base); {
	case strings.HasPrefix(base, "python"):
		return "Python"
	case base == "node" || base == "nodejs":
		return "Node.js"
	case base == "deno":
		return "Deno"
	case base == "bun":
		return "Bun"
	case base == "java":
		return "JVM"
	case base == "ruby":
		return "Ruby"
	case base == "perl":
		return "Perl"
	default:
		return ""
	}
}
