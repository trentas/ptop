package tui

import (
	"github.com/charmbracelet/lipgloss"
)

// renderOverviewView (F1) — segue assets/mockup.jsx → OverviewView
//
// Layout (2 colunas, ratios 2 e 1.3):
//
//   ┌── CPU ──────────────┐    ┌── I/O Throughput ────┐
//   │ [sparkline]   34%   │    │ [dual sparkline]     │
//   └─────────────────────┘    │ stats line           │
//   ┌── Top Syscalls ─────┐    └──────────────────────┘
//   │ epoll_wait ▇▇▇  120 │    ┌── File Descriptors ──┐
//   │ ...                 │    │ open fds          15 │
//   └─────────────────────┘    │ file/socket/pipe...  │
//   ┌── Threads ──────────┐    └──────────────────────┘
//   │ ▶ main 34%          │    ┌── Network ───────────┐
//   │ ■ worker-1 mutex-A  │    │ TCP 10.0.1.5  WAIT … │
//   └─────────────────────┘    └──────────────────────┘
//                              ┌── Memory ────────────┐
//                              │ RSS  148 MB ...      │
//                              └──────────────────────┘
//                              ┌── Event Stream ──────┐
//                              │ 12:34:56 SYS read    │
//                              └──────────────────────┘
func renderOverviewView(m Model, w, h int) string {
	if w < 40 || h < 10 {
		return MutedStyle.Render("(terminal pequeno demais)")
	}

	leftW, rightW := splitOverviewWidth(w)
	leftHs := splitFlex([]float64{1.0, 1.5, 1.4}, h)
	rightHs := splitFlex([]float64{1.1, 0.9, 0.9, 0.65, 1.8}, h)

	// Coluna esquerda
	cpu := Panel("CPU",
		renderCPU(m.CPUHistory, leftW-2),
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
		renderNetMini(m.NetConns, rightW-2, rightHs[2]-3),
		rightW, rightHs[2])

	memPanel := Panel("Memory",
		renderMemMini(m.MemStats, rightW-2),
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
