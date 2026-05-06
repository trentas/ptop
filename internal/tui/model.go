package tui

import (
	"fmt"
	"math"
	"math/rand"
	"os"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/trentas/xray/internal/collector"
)

// simInterval define a granularidade da simulação. O TickMsg dispara no FPS
// (5/s por padrão) para manter o relógio fluido, mas a sim só avança quando
// passa esse intervalo. 700ms é o sweet-spot do mockup React e produz mudanças
// visíveis sem o efeito "tudo pulando".
const simInterval = 700 * time.Millisecond

// topRefreshInterval define quando a lista de top-syscalls/top-files é
// reordenada. Entre refreshes, mesmas linhas com counts atualizados — evita
// bagunça visual a cada tick.
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

// InputMode descreve qual input modal está ativo (se algum).
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

// Config vem do main via flags CLI.
type Config struct {
	PID    int
	FPS    int
	NoEBPF bool
	Export bool
}

// ─── Mensagens Bubbletea ─────────────────────────────────────────────────────

type TickMsg time.Time
type FDMsg []collector.FDEntry
type CpuMsg collector.CpuSample
type ThreadsMsg []collector.ThreadInfo
type MemMsg collector.MemStats
type IOWaitMsg collector.IOWaitSample
type IOThroughputMsg collector.IOThroughputSample
type TimelineMsg collector.TimelineEvent
type FDEventMsg collector.FDEvent
type SyscallsMsg map[string]uint64
type IOEBPFMsg collector.IOEBPFSnapshot
type NetMsg []collector.NetConn
type LockGraphMsg []collector.LockEntry
type LockTimelineMsg collector.TimelineEvent

// exportTickMsg dispara periodicamente quando export contínuo está ON.
type exportTickMsg time.Time

// clearToastMsg apaga o toast/status temporário do statusbar após N segundos.
type clearToastMsg struct{}

// ─── Model ───────────────────────────────────────────────────────────────────

type Model struct {
	cfg Config

	// Identificação
	ProcessName string
	Runtime     string
	State       string
	StartedAt   time.Time

	// Dados coletados
	CPUHistory     []float64
	SyscallCounts  map[string]uint64
	NetConns       []collector.NetConn
	MemStats       collector.MemStats
	Threads        []collector.ThreadInfo
	IOStats        collector.IOStats
	IOReadHist     []float64
	IOWriteHist    []float64
	FDs            []collector.FDEntry
	FDCountHistory []float64
	FDEvents       []collector.FDEvent
	Timeline       []collector.TimelineEvent
	LockGraph      []collector.LockEntry

	// Estado da UI
	ActiveTab int
	FDFilter  string
	Paused    bool
	Width     int
	Height    int

	// Toast: mensagem temporária no statusbar (ex: "snapshot salvo em /tmp/xxx").
	// Vazio quando não há toast ativo. clearToastMsg apaga após 2s.
	toast string

	// Export contínuo (tecla 'e' ou flag --export):
	// quando exportFile != nil, exportTickMsg agenda a próxima escrita JSONL.
	exportFile *os.File

	// Filter: substring aplicada às listas das views (FD/threads/syscalls).
	// inputMode é InputModeFilter quando o usuário está digitando — inputBuf
	// é o que está sendo composto. Após Enter, vira filter; após Esc, descartado.
	filter    string
	inputMode InputMode
	inputBuf  string

	// showHelp: quando true, View() renderiza overlay com keybindings sobre
	// o conteúdo. Fechado por `?`, `esc` ou `q`. Setas/PgUp/PgDn fazem scroll
	// quando o overlay não cabe na altura disponível.
	showHelp   bool
	helpScroll int

	// Collectors
	fdCollector           *collector.FDCollector
	cpuCollector          *collector.CPUCollector
	cpuEBPF               *collector.CPUEBPFCollector
	threadsCollector      *collector.ThreadsCollector
	memCollector          *collector.MemCollector
	iowaitCollector       *collector.IOWaitCollector
	ioThroughputCollector *collector.IOThroughputCollector
	syscallsEBPF          *collector.SyscallsEBPFCollector
	ioEBPF                *collector.IOEBPFCollector
	networkEBPF           *collector.NetworkEBPFCollector
	threadsEBPF           *collector.ThreadsEBPFCollector
	memEBPF               *collector.MemEBPFCollector
	futexEBPF             *collector.FutexEBPFCollector

	// Simulação
	rng                  *rand.Rand
	tickN                int
	usingMockFDs         bool
	usingMockCPU         bool
	usingMockThreads     bool
	usingMockMem         bool
	usingMockIOWait      bool
	usingMockIOThrough   bool
	usingMockSyscalls    bool
	usingMockIOFiles     bool
	usingMockNet         bool
	lastSimAt            time.Time

	// Sources: indicam de onde veio o dado real ("eBPF" | "/proc" | "" pra mock).
	// Mostrado no help overlay (?) pra debug e visibilidade.
	cpuSource      string
	syscallsSource string
	ioFilesSource  string
	netSource      string
	threadsSource  string
	memSource      string
	locksSource    string

	// Caches estáveis para evitar reordenação visual entre ticks.
	// topSyscallNames é recomputado a cada `topRefreshInterval`; entre refreshes
	// renderizamos a mesma lista (em ordem alfabética) com counts atualizados.
	topSyscallNames []string
	topFilesPaths   []string
	lastTopRefresh  time.Time

	// IO maxima com decay lento — evita rescale dos sparklines a cada tick.
	ioMaxRead  float64
	ioMaxWrite float64
}

// ─── Construção ──────────────────────────────────────────────────────────────

func NewModel(cfg Config) Model {
	m := Model{
		cfg:              cfg,
		ProcessName:      detectProcessName(cfg.PID),
		Runtime:          "Go 1.22",
		State:            "RUNNING",
		StartedAt:        time.Now(),
		ActiveTab:        TabOverview,
		FDFilter:         "all",
		SyscallCounts:    make(map[string]uint64),
		rng:              rand.New(rand.NewSource(time.Now().UnixNano())),
		usingMockFDs:     true,
		usingMockCPU:     true,
		usingMockThreads: true,
		usingMockMem:     true,
		usingMockIOWait:    true,
		usingMockIOThrough: true,
		usingMockSyscalls:  true,
		usingMockIOFiles:   true,
		usingMockNet:       true,
	}

	m.seedMockData()

	// Tenta iniciar collectors reais que leem /proc (Linux only).
	// Falha silenciosa em macOS/Windows: usingMock* permanece true e o model
	// continua simulando aquele subsistema.
	if cfg.PID > 0 {
		if c := collector.NewFDCollector(); c.Start(cfg.PID) == nil {
			m.fdCollector = c
			m.usingMockFDs = false
		} else if !cfg.NoEBPF {
			fmt.Fprintf(os.Stderr, "aviso: FD collector indisponível\n")
		}
		// CPU: tenta eBPF perf_event primeiro (granularidade 100Hz/CPU);
		// se falhar (sem -tags=ebpf, sem caps, etc.), cai pra /proc polling.
		// Erro de eBPF é exposto em stderr ANTES do alt-screen pra usuário ver.
		if !cfg.NoEBPF {
			c := collector.NewCPUEBPFCollector()
			if err := c.Start(cfg.PID); err == nil {
				m.cpuEBPF = c
				m.usingMockCPU = false
				m.cpuSource = "eBPF"
			} else {
				fmt.Fprintf(os.Stderr, "aviso: eBPF cpu collector indisponível: %v\n", err)
			}
		}
		if m.cpuEBPF == nil {
			if c := collector.NewCPUCollector(); c.Start(cfg.PID) == nil {
				m.cpuCollector = c
				m.usingMockCPU = false
				m.cpuSource = "/proc"
			}
		}
		// Threads: eBPF preferred (sched_switch dá CPU% real-time + ctx switches),
		// /proc como fallback. eBPF coletor já lê /proc internamente, então não
		// precisamos rodar os dois em paralelo.
		if !cfg.NoEBPF {
			c := collector.NewThreadsEBPFCollector()
			if err := c.Start(cfg.PID); err == nil {
				m.threadsEBPF = c
				m.usingMockThreads = false
				m.threadsSource = "eBPF"
			} else {
				fmt.Fprintf(os.Stderr, "aviso: eBPF threads collector indisponível: %v\n", err)
			}
		}
		if m.threadsEBPF == nil {
			if c := collector.NewThreadsCollector(); c.Start(cfg.PID) == nil {
				m.threadsCollector = c
				m.usingMockThreads = false
				m.threadsSource = "/proc"
			}
		}
		// Memory: eBPF preferred (allocs/s reais via mmap+brk syscalls,
		// page_faults real-time via kprobe handle_mm_fault). /proc-only
		// fallback usa /proc/<pid>/stat que cumula minflt+majflt.
		if !cfg.NoEBPF {
			c := collector.NewMemEBPFCollector()
			if err := c.Start(cfg.PID); err == nil {
				m.memEBPF = c
				m.usingMockMem = false
				m.memSource = "eBPF"
			} else {
				fmt.Fprintf(os.Stderr, "aviso: eBPF memory collector indisponível: %v\n", err)
			}
		}
		if m.memEBPF == nil {
			if c := collector.NewMemCollector(); c.Start(cfg.PID) == nil {
				m.memCollector = c
				m.usingMockMem = false
				m.memSource = "/proc"
			}
		}
		if c := collector.NewIOWaitCollector(); c.Start(cfg.PID) == nil {
			m.iowaitCollector = c
			m.usingMockIOWait = false
		}
		if c := collector.NewIOThroughputCollector(); c.Start(cfg.PID) == nil {
			m.ioThroughputCollector = c
			m.usingMockIOThrough = false
		}
		// Coletor eBPF: só funciona em build com -tags=ebpf, kernel >= 5.8
		// e CAP_BPF/CAP_PERFMON. Erro vai pra stderr pra usuário ver.
		if !cfg.NoEBPF {
			c := collector.NewSyscallsEBPFCollector()
			if err := c.Start(cfg.PID); err == nil {
				m.syscallsEBPF = c
				m.usingMockSyscalls = false
				m.syscallsSource = "eBPF"
			} else {
				fmt.Fprintf(os.Stderr, "aviso: eBPF syscalls collector indisponível: %v\n", err)
			}

			c2 := collector.NewIOEBPFCollector()
			if err := c2.Start(cfg.PID); err == nil {
				m.ioEBPF = c2
				m.usingMockIOFiles = false
				m.ioFilesSource = "eBPF"
			} else {
				fmt.Fprintf(os.Stderr, "aviso: eBPF io collector indisponível: %v\n", err)
			}

			c3 := collector.NewNetworkEBPFCollector()
			if err := c3.Start(cfg.PID); err == nil {
				m.networkEBPF = c3
				m.usingMockNet = false
				m.netSource = "eBPF"
			} else {
				fmt.Fprintf(os.Stderr, "aviso: eBPF network collector indisponível: %v\n", err)
			}

			c4 := collector.NewFutexEBPFCollector()
			if err := c4.Start(cfg.PID); err == nil {
				m.futexEBPF = c4
				m.locksSource = "eBPF"
			} else {
				fmt.Fprintf(os.Stderr, "aviso: eBPF futex collector indisponível: %v\n", err)
			}
		}
	}

	// --export: abre o arquivo JSONL desde já. Se falhar, apenas avisa
	// (não bloqueia o launch — usuário ainda usa a TUI normalmente).
	if cfg.Export {
		if f, err := openExportFile(); err == nil {
			m.exportFile = f
			m.toast = fmt.Sprintf("✓ export: %s", f.Name())
		} else {
			fmt.Fprintf(os.Stderr, "aviso: --export falhou: %v\n", err)
		}
	}

	return m
}

// ─── Init / Update / View ────────────────────────────────────────────────────

func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{tick(m.cfg.FPS)}
	if m.fdCollector != nil {
		cmds = append(cmds, waitForFD(m.fdCollector))
	}
	if m.cpuCollector != nil {
		cmds = append(cmds, waitForCPU(m.cpuCollector))
	}
	if m.cpuEBPF != nil {
		cmds = append(cmds, waitForCPUEBPF(m.cpuEBPF))
	}
	if m.threadsCollector != nil {
		cmds = append(cmds, waitForThreads(m.threadsCollector))
	}
	if m.memCollector != nil {
		cmds = append(cmds, waitForMem(m.memCollector))
	}
	if m.iowaitCollector != nil {
		cmds = append(cmds, waitForIOWait(m.iowaitCollector))
	}
	if m.ioThroughputCollector != nil {
		cmds = append(cmds, waitForIOThroughput(m.ioThroughputCollector))
	}
	if m.syscallsEBPF != nil {
		cmds = append(cmds, waitForSyscalls(m.syscallsEBPF))
	}
	if m.ioEBPF != nil {
		cmds = append(cmds, waitForIOEBPF(m.ioEBPF))
	}
	if m.networkEBPF != nil {
		cmds = append(cmds, waitForNetEBPF(m.networkEBPF))
	}
	if m.threadsEBPF != nil {
		cmds = append(cmds, waitForThreadsEBPF(m.threadsEBPF))
	}
	if m.memEBPF != nil {
		cmds = append(cmds, waitForMemEBPF(m.memEBPF))
	}
	if m.futexEBPF != nil {
		cmds = append(cmds, waitForFutexEBPF(m.futexEBPF))
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
		// Render no FPS configurado (clock/uptime ficam suaves), mas a simulação
		// só avança a cada simInterval — evita o "tudo pulando" por overshoot
		// de mudanças por segundo. Quando o frame fica idêntico, bubbletea
		// detecta diff vazio e nem repinta.
		if !m.Paused && time.Since(m.lastSimAt) >= simInterval {
			m.tick()
			m.lastSimAt = time.Now()
		}
		return m, tick(m.cfg.FPS)

	case FDMsg:
		m.FDs = []collector.FDEntry(v)
		m.usingMockFDs = false
		m.FDCountHistory = appendCapped(m.FDCountHistory, float64(len(m.FDs)), 60)
		return m, waitForFD(m.fdCollector)

	case TimelineMsg:
		// Timeline é prepend; mais recente em cima. Cap em 120 (mesmo limite
		// usado pela simulação).
		m.Timeline = append([]collector.TimelineEvent{collector.TimelineEvent(v)}, m.Timeline...)
		if len(m.Timeline) > 120 {
			m.Timeline = m.Timeline[:120]
		}
		return m, waitForFD(m.fdCollector)

	case FDEventMsg:
		m.FDEvents = append([]collector.FDEvent{collector.FDEvent(v)}, m.FDEvents...)
		if len(m.FDEvents) > 60 {
			m.FDEvents = m.FDEvents[:60]
		}
		return m, waitForFD(m.fdCollector)

	case CpuMsg:
		s := collector.CpuSample(v)
		m.CPUHistory = appendCapped(m.CPUHistory, s.UsagePct, 60)
		m.usingMockCPU = false
		// Reagenda na source ativa: eBPF tem prioridade quando disponível.
		if m.cpuEBPF != nil {
			return m, waitForCPUEBPF(m.cpuEBPF)
		}
		return m, waitForCPU(m.cpuCollector)

	case ThreadsMsg:
		m.Threads = []collector.ThreadInfo(v)
		m.usingMockThreads = false
		// ThreadsMsg pode vir do eBPF ou do /proc — reagenda a fonte ativa.
		if m.threadsEBPF != nil {
			return m, waitForThreadsEBPF(m.threadsEBPF)
		}
		return m, waitForThreads(m.threadsCollector)

	case MemMsg:
		m.MemStats = collector.MemStats(v)
		m.usingMockMem = false
		// Reagenda na fonte ativa.
		if m.memEBPF != nil {
			return m, waitForMemEBPF(m.memEBPF)
		}
		return m, waitForMem(m.memCollector)

	case IOWaitMsg:
		m.IOStats.IOWaitPct = collector.IOWaitSample(v).Pct
		m.usingMockIOWait = false
		return m, waitForIOWait(m.iowaitCollector)

	case clearToastMsg:
		m.toast = ""
		return m, nil

	case exportTickMsg:
		// Export contínuo: escreve uma linha JSONL por tick. Se a escrita falhar,
		// fecha o arquivo e mostra toast de erro — não trava a TUI.
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
		// Snapshot completo do map syscall_count vindo do tracer eBPF.
		// Sobrescrevemos o counts inteiro: o tracer mantém o cumulativo per-pid.
		m.SyscallCounts = map[string]uint64(v)
		m.usingMockSyscalls = false
		return m, waitForSyscalls(m.syscallsEBPF)

	case NetMsg:
		m.NetConns = []collector.NetConn(v)
		m.usingMockNet = false
		return m, waitForNetEBPF(m.networkEBPF)

	case LockGraphMsg:
		m.LockGraph = []collector.LockEntry(v)
		return m, waitForFutexEBPF(m.futexEBPF)

	case LockTimelineMsg:
		ev := collector.TimelineEvent(v)
		m.Timeline = append([]collector.TimelineEvent{ev}, m.Timeline...)
		if len(m.Timeline) > 120 {
			m.Timeline = m.Timeline[:120]
		}
		return m, waitForFutexEBPF(m.futexEBPF)

	case IOEBPFMsg:
		s := collector.IOEBPFSnapshot(v)
		m.IOStats.TopFiles = s.TopFiles
		// Buckets agora vêm da janela atual (read+write counts deste intervalo).
		// Mesclamos com os labels existentes pra preservar a ordem.
		if len(s.Buckets) == len(m.IOStats.LatencyBuckets) {
			for i, b := range s.Buckets {
				m.IOStats.LatencyBuckets[i].Read = b.Read
				m.IOStats.LatencyBuckets[i].Write = b.Write
			}
		} else if len(s.Buckets) > 0 {
			m.IOStats.LatencyBuckets = s.Buckets
		}
		m.usingMockIOFiles = false
		return m, waitForIOEBPF(m.ioEBPF)

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
		return m, waitForIOThroughput(m.ioThroughputCollector)
	}
	return m, nil
}

func (m Model) View() string {
	if m.Width == 0 || m.Height == 0 {
		return "iniciando..."
	}

	header := renderHeader(m)
	tabbar := renderTabBar(m)

	// Statusbar é substituído pelo input box quando inputMode == filter
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

	// Help overlay tem prioridade sobre o conteúdo da view
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

	// Garante altura exata para o content (lipgloss truncará se exceder)
	contentBox := lipgloss.NewStyle().
		Width(contentW).
		Height(contentH).
		MaxHeight(contentH).
		Background(ColorBG).
		Render(content)

	return header + "\n" + tabbar + "\n" + contentBox + "\n" + statusbar
}

// ─── Simulação ───────────────────────────────────────────────────────────────

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

	// Timeline (semeada vazia — vai sendo preenchida pelo tick)
	m.Timeline = make([]collector.TimelineEvent, 0, 120)
	m.FDEvents = make([]collector.FDEvent, 0, 60)

	// Inicializa caches estáveis e máximos com decay
	m.refreshTopN()
	m.lastTopRefresh = time.Now()
	m.lastSimAt = time.Now()

	// Estima máximos iniciais a partir do histórico semeado
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

	// Pré-popula com alguns eventos para a UI não começar vazia
	for i := 0; i < 12; i++ {
		m.pushTimeline()
		m.maybePushFDEvent()
	}
}

// refreshTopN recomputa quais syscalls/arquivos aparecem no top — em ordem
// alfabética para que entre refreshes a posição visual não mude. Os counts
// continuam atualizados a cada tick; só o conjunto+ordem é congelado.
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

// tick avança a simulação um passo. Chamado pelo TickMsg quando não está em pause.
// Em modo eBPF real, esta função coexistirá com mensagens dos collectors:
// os campos atualizados aqui são sobrescritos quando uma mensagem real chegar.
func (m *Model) tick() {
	m.tickN++
	r := m.rng

	// CPU — só simula se collector real não está rodando.
	// Quando real, o campo é alimentado via CpuMsg.
	if m.usingMockCPU {
		prev := 20.0
		if len(m.CPUHistory) > 0 {
			prev = m.CPUHistory[len(m.CPUHistory)-1]
		}
		delta := (r.Float64()*2 - 0.9) * 12
		cpu := clamp(prev+delta, 0, 100)
		m.CPUHistory = appendCapped(m.CPUHistory, cpu, 60)
	}

	// Syscalls — só simula se o eBPF tracer não está rodando.
	if m.usingMockSyscalls {
		for i := 0; i < 3; i++ {
			k := simSyscalls[r.Intn(len(simSyscalls))]
			m.SyscallCounts[k] += uint64(r.Intn(20))
		}
	}

	// Memory — só simula se collector real não está rodando
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

	// Network — jitter de latência + estado oscilante. Só simulamos quando
	// o eBPF network collector não está rodando.
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

	// Threads — só simula se collector real não está rodando
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

	// I/O throughput — só simula se collector real não está rodando
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

		// Máximo "decay": cresce no instante do pico e cai 3% por tick.
		// Isso evita rescale brusco do sparkline cada vez que aparece um valor
		// alto isolado e depois some.
		const decayPerTick = 0.97
		m.ioMaxRead = math.Max(m.ioMaxRead*decayPerTick, nr)
		m.ioMaxWrite = math.Max(m.ioMaxWrite*decayPerTick, nw)
		if m.ioMaxRead < 100*1024 { // piso visual: 100KB/s
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

	// TopFiles + LatencyBuckets só simulam quando o eBPF io collector
	// não está rodando — quando rodando, IOEBPFMsg substitui esses campos.
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

	// FDs — só simulamos quando não há collector real plugado
	if m.usingMockFDs {
		m.simulateFDs()
	}

	// Timeline + FD events — empilha 1 a cada tick (em média)
	if r.Float64() > 0.3 {
		m.pushTimeline()
	}
	if r.Float64() > 0.5 {
		m.maybePushFDEvent()
	}

	// Top-N: re-ordena raramente para evitar reorder visual a cada tick
	if time.Since(m.lastTopRefresh) >= topRefreshInterval {
		m.refreshTopN()
		m.lastTopRefresh = time.Now()
	}
}

func (m *Model) simulateFDs() {
	r := m.rng

	// Atualiza idade + bytes
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

	// Ocasionalmente abre um novo FD
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

	// Ocasionalmente fecha um FD descartável (fd > 10)
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
	// prepend (mais recente primeiro)
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

// exportInterval define quão frequentemente o export contínuo grava uma
// linha JSONL. simInterval (700ms) seria muito barulhento — 2s é um
// compromise entre granularidade e tamanho do arquivo gerado.
const exportInterval = 2 * time.Second

func exportTick() tea.Cmd {
	return tea.Tick(exportInterval, func(t time.Time) tea.Msg { return exportTickMsg(t) })
}

// toastTTL é quanto tempo a mensagem temporária no statusbar fica visível.
const toastTTL = 2 * time.Second

func clearToastAfter(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(time.Time) tea.Msg { return clearToastMsg{} })
}

// Close libera recursos abertos pelo model — atualmente o arquivo de export.
// main.go chama isso após p.Run() retornar pra garantir flush.
func (m Model) Close() {
	if m.exportFile != nil {
		_ = m.exportFile.Close()
	}
}

// waitForFD bloqueia até receber uma mensagem do FD collector e a entrega ao Update.
// O FDCollector publica 3 tipos diferentes na mesma channel; demuxamos via
// type-switch e mapeamos pra tea.Msg específica.
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

// detectProcessName lê /proc/<pid>/comm pra obter o nome curto do processo
// (kernel TASK_COMM_LEN = 16 chars). Em macOS/Windows, fallback pra "(?)" —
// indica claramente que estamos em modo simulado.
func detectProcessName(pid int) string {
	if pid <= 0 {
		return "(?)"
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "(?)"
	}
	name := strings.TrimSpace(string(data))
	if name == "" {
		return "(?)"
	}
	return name
}

