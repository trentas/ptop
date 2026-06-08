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

// NetError is a kernel-observed network failure (#56), correlated to a
// connection by its peer 5-tuple. Kind is "refused" (RST while still
// connecting), "reset" (RST mid-stream), or "retransmit" (a tcp_retransmit_skb
// fired). DetailMs is the latency from the relevant baseline to the RST
// (SYN_SENT→RST for refused, ESTABLISHED→RST for reset); 0 for retransmit.
// Retransmits is the connection's running retransmit count at event time — the
// live count for "retransmit", or how many retransmits preceded an RST.
type NetError struct {
	Timestamp   time.Time
	Kind        string
	Remote      string // peer host:port
	Retransmits uint32
	DetailMs    float64
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

// FSEvent is a kernel-observed filesystem *semantic* event (#57): a permission
// denial on open/openat ("denied"), a delete ("deleted"), or a rename
// ("renamed"), captured with the real path(s). Op carries the semantic verb;
// Errno/Err carry the syscall result (0/"" on success — deletes and renames are
// emitted on success too, denials only on EACCES/EPERM). NewPath is the rename
// destination, "" otherwise. Emitted only by the eBPF io collector (never
// simulated); paths are kernel-truncated to 255 bytes.
type FSEvent struct {
	Timestamp time.Time
	Op        string // "denied" | "deleted" | "renamed"
	Path      string
	NewPath   string // rename destination; "" otherwise
	Errno     int32  // 0 on success; positive errno (EACCES=13, EPERM=1, …)
	Err       string // "EACCES" | "EPERM" | "ENOENT" | "" …
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

// ─── Signals (#58) ─────────────────────────────────────────────────────────

// SignalEvent is a signal DELIVERED TO the target, captured at kernel
// generation time (signal:signal_generate) — including who sent it. Signal is
// the symbolic name ("SIGPIPE"); SenderPID/SenderComm identify the sending
// process (for kernel-generated signals like SIGSEGV the sender is the target
// itself). TargetTID is the receiving thread. Code is si_code (SI_USER,
// SI_KERNEL, …) — a root-cause hint; Result is the kernel's TRACE_SIGNAL_*
// disposition (delivered/ignored/blocked). Emitted only by the eBPF signal
// collector (never simulated).
type SignalEvent struct {
	Timestamp  time.Time
	Signal     string // "SIGPIPE", "SIGTERM", … (or "SIG<n>" for the unnamed)
	Signo      int32
	SenderPID  int32
	SenderComm string
	TargetTID  int32
	Code       int32 // si_code
	Result     int32 // TRACE_SIGNAL_* disposition
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
