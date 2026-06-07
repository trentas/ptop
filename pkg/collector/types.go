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

// ─── Heap allocations (eBPF libc malloc/free pairing — #53) ───────────────────

// HeapEvent is a single allocation or free observed via libc uprobes.
// Op is "malloc"|"calloc"|"realloc"|"free". LifetimeMs is set on free
// (free.ts − alloc.ts). CallSite is the application call-site address (raw
// instruction pointer; the aggregate HeapCallSite carries the symbolized form).
// StackID is the kernel stack-map id of the captured stack (<0 when the walk
// failed), resolvable to full frames out-of-band. Large flags allocations ≥ 128KB.
type HeapEvent struct {
	Op         string
	Size       uint64
	Addr       uint64
	LifetimeMs float64
	CallSite   uint64
	StackID    int32
	Large      bool
}

// HeapCallSite aggregates the currently-live allocations attributed to one
// application call site (by the alloc-site stack, so a free decrements the site
// it was allocated from).
//
// CallSite is the raw instruction pointer; Func/File/Line/Module/Offset are its
// symbolization (#54). Func is "" when the address can't be resolved to a
// function (stripped non-Go module — Module+Offset still locate it); File/Line
// are set only for Go modules in this cut (C/C++ file:line needs DWARF). AddrHex
// is the raw-address fallback ("0x…", or "unknown" when the stack walk failed).
type HeapCallSite struct {
	CallSite      uint64  // raw application instruction pointer
	AddrHex       string  // "0x…" raw-address fallback ("unknown" when unresolved)
	Func          string  // resolved function name ("" if unresolved)
	File          string  // source file (Go only in this cut; "" otherwise)
	Line          int     // source line (0 if unknown)
	Module        string  // backing module basename ("" if unresolved)
	Offset        uint64  // module-relative offset of the call site
	StackID       int32   // kernel stack-map id (<0 unknown); resolves to full frames
	LiveBytes     uint64  // bytes still live from this site
	AllocCount    uint64  // total allocations ever from this site
	AvgLifetimeMs float64 // mean lifetime of freed allocations from this site
	Suspected     bool    // has live allocations older than the leak threshold
}

// HeapStats is the periodic snapshot of heap behavior. LiveHeapBytes and
// SuspectedLeakBytes derive from the kernel's live set, which LRU-evicts under
// pressure — so both UNDERCOUNT on alloc-heavy targets (see heap.bpf.c); never
// presented as exact. AllocRate is allocations per second over the last window.
type HeapStats struct {
	Timestamp          time.Time
	LiveHeapBytes      uint64
	AllocRate          float64
	TopCallSites       []HeapCallSite
	SuspectedLeakBytes uint64
}

// ─── Threads ─────────────────────────────────────────────────────────────────

type ThreadInfo struct {
	TID     int
	Name    string
	State   string // "running" | "blocked" | "sleeping"
	CPUPct  float64
	Waiting string // name of the blocking lock/syscall, empty if none
	// CtxSwitches: total context switches for the thread within the current
	// window (interval between collector publishes). Only populated when the
	// eBPF threads collector is active; via /proc this stays zero.
	CtxSwitches uint64
}

// ─── Locks (futex) ───────────────────────────────────────────────────────────

// LockEntry describes a contended futex: cumulative WAITs and WAKEs observed
// on the uaddr (virtual address of the futex word), plus average call
// latency and the last waiter/waker.
//
// UAddr is the virtual pointer in the process address space — without
// unwind/symbols we can't resolve it to "mutex-A". We display it in hex.
type LockEntry struct {
	UAddr       uint64
	Waiters     uint64  // cumulative wait_count
	Wakers      uint64  // cumulative wake_count
	WaitDelta   uint64  // new waits in the current window
	LatencyMs   float64 // average latency per call (waits + wakes)
	LastWaitTID int
	LastWakeTID int
}

// ─── I/O ─────────────────────────────────────────────────────────────────────

// IOWaitSample is the fraction of wallclock the process spent blocked on
// synchronous block I/O during the last interval. Computed by the collector
// reading /proc/<pid>/stat field 42 (delayacct_blkio_ticks).
type IOWaitSample struct {
	Pct       float64
	Timestamp time.Time
}

// IOThroughputSample is the snapshot of process I/O throughput in the last
// interval. ReadBytesPerS/WriteBytesPerS are instantaneous rates; ReadOps/
// WriteOps are CUMULATIVE since the process started (same semantics as
// /proc/<pid>/io). Computed by the collector reading /proc/<pid>/io.
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

// FDEvent is a granular event from the FD stream (openat/close/dup2/...).
// Unlike the []FDEntry snapshot which is the full current state, FDEvent
// is a change notification — used to feed the F6 ▸ FD Events panel.
type FDEvent struct {
	Timestamp time.Time
	Message   string
}

type FDEntry struct {
	FD     int
	Type   string // "file" | "socket" | "pipe" | "epoll" | "timer" | "event"
	Desc   string // full path or remote address
	Flags  string // "O_RDONLY" | "O_WRONLY" | "O_RDWR"
	Bytes  uint64
	AgeMs  int64
	Active bool // had activity in the last cycle
}

// ─── Timeline ────────────────────────────────────────────────────────────────

type TimelineEvent struct {
	Timestamp time.Time
	Category  string // "syscall"|"net"|"mem"|"cpu"|"lock"|"io"|"fd"
	Message   string
}

// ─── Collector interface ─────────────────────────────────────────────────────

// Collector is implemented by each collection subsystem.
// Subscribe returns a channel of typed messages (CpuSample, SyscallEvent, etc).
// The Bubbletea model selects on all channels via tea.Cmd.
type Collector interface {
	Start(pid int) error
	Stop()
	Subscribe() <-chan interface{}
}
