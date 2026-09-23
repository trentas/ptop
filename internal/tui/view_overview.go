package tui

import (
	"github.com/charmbracelet/lipgloss"
)

// renderOverviewView (F1) — segue assets/mockup.jsx → OverviewView
//
// Layout (2 colunas, ratios 2 e 1.3):
//
//	┌── CPU ──────────────┐    ┌── I/O Throughput ────┐
//	│ [sparkline]   34%   │    │ [dual sparkline]     │
//	└─────────────────────┘    │ stats line           │
//	┌── Top Syscalls ─────┐    └──────────────────────┘
//	│ epoll_wait ▇▇▇  120 │    ┌── File Descriptors ──┐
//	│ ...                 │    │ open fds          15 │
//	└─────────────────────┘    │ file/socket/pipe...  │
//	┌── Threads ──────────┐    └──────────────────────┘
//	│ ▶ main 34%          │    ┌── Network ───────────┐
//	│ ■ worker-1 mutex-A  │    │ TCP 10.0.1.5  WAIT … │
//	└─────────────────────┘    └──────────────────────┘
//	                           ┌── Memory ────────────┐
//	                           │ RSS  148 MB ...      │
//	                           └──────────────────────┘
//	                           ┌── Event Stream ──────┐
//	                           │ 12:34:56 SYS read    │
//	                           └──────────────────────┘
func renderOverviewView(m Model, w, h int) string {
	if w < minTerminalWidth || h < minContentHeight {
		return MutedStyle.Render("(terminal too small)")
	}

	leftW, rightW := splitOverviewWidth(w)

	// The CPU panel grows to fit the attribution list (#125) only when the
	// sampler has produced something, the same way the Memory panel grows for
	// the heap detail below; without it the panel keeps the mockup's compact
	// sparkline layout and the other two keep their height.
	cpuSites := m.CPUSites.fold()
	cpuRatio, syscallRatio, threadRatio := 1.0, 1.5, 1.4
	if cpuSites.WindowMs > 0 {
		cpuRatio, syscallRatio, threadRatio = 1.55, 1.25, 1.1
	}
	leftHs := splitFlex([]float64{cpuRatio, syscallRatio, threadRatio}, h)

	// The Memory panel grows to fit the heap detail (live-heap sparkline + top
	// call sites) only when the eBPF heap collector (#53) has data; otherwise it
	// keeps the compact mockup layout and the Event Stream keeps its height.
	memRatio, evRatio := 0.65, 1.8
	if len(m.HeapStats.TopCallSites) > 0 {
		memRatio, evRatio = 1.55, 0.9
	}
	rightHs := splitFlex([]float64{1.1, 0.9, 0.9, memRatio, evRatio}, h)

	// Coluna esquerda
	cpu := Panel("CPU",
		renderCPU(m.CPUHistory, cpuSites, leftW-2, leftHs[0]-3),
		leftW, leftHs[0])

	syscalls := Panel("Top Syscalls",
		renderSyscallBars(m.SyscallCounts, m.topSyscallNames, leftW-2, leftHs[1]-3),
		leftW, leftHs[1])

	threads := Panel("Threads",
		renderThreadList(m.Threads, leftW-2, leftHs[2]-3),
		leftW, leftHs[2])

	leftCol := lipgloss.JoinVertical(lipgloss.Left, cpu, syscalls, threads)

	// Coluna direita
	ioPanel := Panel("I/O Throughput",
		renderIOMini(m.IOStats, m.IOReadHist, m.IOWriteHist, m.ioMaxRead, m.ioMaxWrite, rightW-2),
		rightW, rightHs[0])

	fdPanel := Panel("File Descriptors",
		renderFDMini(m.FDs, rightW-2),
		rightW, rightHs[1])

	netPanel := Panel("Network",
		renderNetMini(m.NetConns, rightW-2, rightHs[2]-3, false),
		rightW, rightHs[2])

	memPanel := Panel("Memory",
		renderMemMini(m.MemStats, m.HeapStats, m.HeapLiveHist, rightW-2, rightHs[3]-3),
		rightW, rightHs[3])

	timelinePanel := Panel("Event Stream",
		renderTimelineCompact(m.Timeline, rightW-2, rightHs[4]-3),
		rightW, rightHs[4])

	rightCol := lipgloss.JoinVertical(lipgloss.Left, ioPanel, fdPanel, netPanel, memPanel, timelinePanel)

	return lipgloss.JoinHorizontal(lipgloss.Top, leftCol, rightCol)
}

// splitOverviewWidth divide w em duas colunas com ratio 2 : 1.3.
func splitOverviewWidth(w int) (int, int) {
	left := w * 20 / 33 // ≈ w * 0.606
	if left < 30 {
		left = 30
	}
	if left > w-20 {
		left = w - 20
	}
	if left < 1 {
		left = w / 2
	}
	right := w - left
	return left, right
}
