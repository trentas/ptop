package collector

import "time"

// ─── CPU ─────────────────────────────────────────────────────────────────────

type CpuSample struct {
	UsagePct  float64
	Timestamp time.Time
}

// ─── Syscalls ─────────────────────────────────────────────────────────────────

type SyscallEvent struct {
	Name      string
	Count     uint64
	LatencyNs uint64
}

// ─── Network ─────────────────────────────────────────────────────────────────

type NetConn struct {
	FD        int
	Type      string // "TCP" | "UDP" | "UNIX"
	Remote    string
	State     string // "ESTABLISHED" | "WAIT" | "RECV" | "LISTEN"
	Dir       string // "→" | "←" | "↔"
	LatencyMs float64
	TxBytes   uint64
	RxBytes   uint64
}

// ─── Memory ───────────────────────────────────────────────────────────────────

type MemStats struct {
	RSSBytes   uint64
	HeapBytes  uint64
	PageFaults uint64
	AllocsPerS uint64
}

// ─── Threads ─────────────────────────────────────────────────────────────────

type ThreadInfo struct {
	TID     int
	Name    string
	State   string  // "running" | "blocked" | "sleeping"
	CPUPct  float64
	Waiting string  // nome do lock/syscall bloqueante, vazio se nenhum
}

// ─── I/O ─────────────────────────────────────────────────────────────────────

// IOWaitSample é a fração do wallclock que o processo passou bloqueado em
// block I/O síncrono no último intervalo. Calculado pelo collector que lê
// /proc/<pid>/stat campo 42 (delayacct_blkio_ticks).
type IOWaitSample struct {
	Pct       float64
	Timestamp time.Time
}

// IOThroughputSample é o snapshot do throughput de I/O do processo no último
// intervalo. ReadBytesPerS/WriteBytesPerS são taxas instantâneas; ReadOps/
// WriteOps são CUMULATIVOS desde o início do processo (mesma semântica de
// /proc/<pid>/io). Calculado pelo collector que lê /proc/<pid>/io.
type IOThroughputSample struct {
	ReadBytesPerS  float64
	WriteBytesPerS float64
	ReadOps        uint64
	WriteOps       uint64
	Timestamp      time.Time
}

type IOEvent struct {
	Op        string // "read" | "write" | "fsync" | "openat" | "stat"
	Path      string
	Bytes     uint64
	LatencyMs float64
	FD        int
}

type IOFileStats struct {
	Path      string
	Type      string // "db" | "log" | "cfg" | "tmp" | "proc"
	Reads     uint64
	Writes    uint64
	Bytes     uint64
	LatencyMs float64
	Fsyncs    uint64
}

type IOStats struct {
	ReadBytesPerS  float64
	WriteBytesPerS float64
	ReadOps        uint64
	WriteOps       uint64
	Fsyncs         uint64
	Opens          uint64
	IOWaitPct      float64
	TopFiles       []IOFileStats
	LatencyBuckets []LatencyBucket
}

type LatencyBucket struct {
	Label string
	Read  float64
	Write float64
}

// ─── File Descriptors ────────────────────────────────────────────────────────

// FDEvent é um evento granular do stream de FDs (openat/close/dup2/...).
// Diferente do snapshot []FDEntry que é o estado atual completo, FDEvent
// é uma notificação de mudança — usado pra alimentar a F6 ▸ FD Events.
type FDEvent struct {
	Timestamp time.Time
	Message   string
}

type FDEntry struct {
	FD     int
	Type   string // "file" | "socket" | "pipe" | "epoll" | "timer" | "event"
	Desc   string // path completo ou endereço remoto
	Flags  string // "O_RDONLY" | "O_WRONLY" | "O_RDWR"
	Bytes  uint64
	AgeMs  int64
	Active bool   // teve atividade no último ciclo
}

// ─── Timeline ────────────────────────────────────────────────────────────────

type TimelineEvent struct {
	Timestamp time.Time
	Category  string // "syscall"|"net"|"mem"|"cpu"|"lock"|"io"|"fd"
	Message   string
}

// ─── Collector interface ─────────────────────────────────────────────────────

// Collector é implementado por cada subsistema de coleta.
// Subscribe retorna um canal de mensagens tipadas (CpuSample, SyscallEvent, etc).
// O model Bubbletea faz select em todos os canais via tea.Cmd.
type Collector interface {
	Start(pid int) error
	Stop()
	Subscribe() <-chan interface{}
}
