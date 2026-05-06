# xray

Interactive TUI for deep inspection of Linux processes via eBPF.
Provides live diagnosis of CPU, syscalls, network, I/O, memory, threads, and file descriptors
of any running process — without restarting, without instrumenting, without changing a line of code.

---

## Stack

| Layer  | Technology | Reason |
|--------|-----------|--------|
| TUI    | [Bubbletea](https://github.com/charmbracelet/bubbletea) + [Lipgloss](https://github.com/charmbracelet/lipgloss) | Mature ecosystem, composable, mouse support |
| eBPF   | [libbpfgo](https://github.com/aquasecurity/libbpfgo) | Official Cilium binding, best CO-RE support |
| Build  | Go 1.22+ | Single binary, easy cross-compile |
| eBPF C | clang + bpftool | Compile .c → .o → embed in the binary via go:generate |

> Don't use CGO beyond what libbpfgo already requires. Don't use CLI frameworks (cobra, urfave) — the entrypoint is simple.

---

## Visual reference

`assets/mockup.jsx` contains the full React prototype with all tabs implemented and simulated data.
**Each Go view must faithfully reproduce the layout of the corresponding mockup.**
Use it as the authoritative visual spec — if there's any doubt about layout, the mockup wins.

Color palette (use via Lipgloss):
```
bg:      #0e1014    bgPanel: #13161c    border:  #2a2d35
dim:     #3a3d45    muted:   #5a5f72    text:    #c8ccd8
bright:  #e8ecf5    green:   #4ade80    cyan:    #22d3ee
amber:   #fbbf24    red:     #f87171    blue:    #60a5fa
purple:  #a78bfa    pink:    #f472b6    orange:  #fb923c
teal:    #2dd4bf
```

---

## Project structure

```
xray/
├── CLAUDE.md
├── go.mod
├── go.sum
├── Makefile
├── cmd/
│   └── inspector/
│       └── main.go          # entrypoint: parse args, init collectors, start TUI
├── internal/
│   ├── bpf/
│   │   ├── programs/        # .c sources for the eBPF programs
│   │   │   ├── syscalls.bpf.c
│   │   │   ├── network.bpf.c
│   │   │   ├── io.bpf.c
│   │   │   └── fds.bpf.c
│   │   ├── loader.go        # loads and manages the eBPF programs
│   │   └── maps.go          # definitions of the shared BPF maps
│   ├── collector/
│   │   ├── types.go         # data structs shared between collectors and TUI
│   │   ├── cpu.go           # perf_event sampling → CPU history
│   │   ├── syscalls.go      # tracepoint syscalls:sys_enter_* → counts + latency
│   │   ├── network.go       # sock tracepoints → active connections, per-peer latency
│   │   ├── memory.go        # mmap/brk/page faults via tracepoints
│   │   ├── threads.go       # sched tracepoints → thread state + off-cpu
│   │   ├── io.go            # block I/O tracepoints → throughput, latency, top files
│   │   └── fds.go           # openat/close/dup2 uprobes → live FD table
│   └── tui/
│       ├── model.go         # Bubbletea root model: global state, msg routing
│       ├── keys.go          # keybindings (F1-F7, q, p, /, s, e)
│       ├── styles.go        # all Lipgloss definitions (colors, borders, badges)
│       ├── header.go        # top bar: name, PID, runtime, fd count badge, uptime
│       ├── tabbar.go        # F1-F7 tab bar
│       ├── statusbar.go     # footer with keybindings and overhead info
│       ├── sparkline.go     # reusable SVG-style braille sparkline component
│       └── views/
│           ├── overview.go  # F1: CPU + syscalls + threads + I/O mini + net + mem + timeline
│           ├── syscalls.go  # F2: frequency bars + percentage + event stream
│           ├── network.go   # F3: active connections + latency trend + net events
│           ├── threads.go   # F4: thread state + lock graph + lock events
│           ├── io.go        # F5: dual throughput + top files + latency histogram + stats
│           ├── fd.go        # F6: fd table + breakdown + sparkline + alerts + fd events
│           └── timeline.go  # F7: full event stream with badge per category
└── assets/
    └── mockup.jsx           # React prototype — authoritative visual reference
```

---

## Core data types (`internal/collector/types.go`)

All collectors publish to typed channels consumed by the Bubbletea model.

```go
// Msg sent by the CPU collector on each tick
type CpuSample struct {
    UsagePct float64
    Timestamp time.Time
}

// Syscall msg
type SyscallEvent struct {
    Name      string
    Count     uint64
    LatencyNs uint64
}

// Active network connection
type NetConn struct {
    FD       int
    Type     string // "TCP" | "UDP" | "UNIX"
    Remote   string
    State    string // "ESTABLISHED" | "WAIT" | "RECV" | ...
    LatencyMs float64
    TxBytes  uint64
    RxBytes  uint64
}

// I/O event
type IOEvent struct {
    Op       string // "read" | "write" | "fsync" | "openat"
    Path     string
    Bytes    uint64
    LatencyMs float64
    FD       int
}

// File descriptor
type FDEntry struct {
    FD       int
    Type     string // "file" | "socket" | "pipe" | "epoll" | "timer"
    Desc     string // path or remote address
    Flags    string // O_RDONLY | O_WRONLY | O_RDWR
    Bytes    uint64
    AgeMs    int64
    Active   bool
}

// Thread
type ThreadInfo struct {
    TID     int
    Name    string
    State   string // "running" | "blocked" | "sleeping"
    CPUPct  float64
    Waiting string // name of the blocking lock/syscall, if any
}

// Generic timeline event
type TimelineEvent struct {
    Timestamp time.Time
    Category  string // "syscall"|"net"|"mem"|"cpu"|"lock"|"io"|"fd"
    Message   string
}
```

---

## Collectors — implementation contract

Each collector implements this interface:

```go
type Collector interface {
    Start(ctx context.Context, pid int) error
    Stop()
    Subscribe() <-chan interface{} // sends the typed msgs above
}
```

The Bubbletea model `select`s across all channels via `tea.Cmd` wrapping `waitForMsg`.

### Implementation priority

1. `syscalls.go` — highest impact, uses stable tracepoints
2. `cpu.go` — perf_event, kernel-version-independent
3. `fds.go` — read `/proc/{pid}/fd` + eBPF events for openat/close
4. `io.go` — block tracepoints
5. `network.go` — sock tracepoints
6. `threads.go` — sched tracepoints
7. `memory.go` — mmap/fault tracepoints

> For the MVP, `fds.go` can poll `/proc/{pid}/fd` every 500ms without eBPF.
> The rest should use eBPF from the start.

---

## TUI — implementation rules

### Bubbletea model

```go
type Model struct {
    // collected data
    CPUHistory    []float64       // last 60 samples
    SyscallCounts map[string]uint64
    NetConns      []collector.NetConn
    MemStats      collector.MemStats
    Threads       []collector.ThreadInfo
    IOStats       collector.IOStats
    FDs           []collector.FDEntry
    Timeline      []collector.TimelineEvent

    // UI state
    ActiveTab     int
    FDFilter      string          // "all"|"file"|"socket"|...
    Paused        bool
    Width, Height int
}
```

### Bubbletea messages

```go
type TickMsg time.Time
type CpuMsg collector.CpuSample
type SyscallMsg []collector.SyscallEvent
type NetMsg []collector.NetConn
type IOMsg collector.IOEvent
type FDMsg []collector.FDEntry
type ThreadMsg []collector.ThreadInfo
type TimelineMsg collector.TimelineEvent
```

### Braille sparkline

Use Unicode braille blocks for sparklines — it's the modern TUI standard.
Characters: `⣀⣄⣆⣇⡇⡏⡟⡿` (8-level scale per column).
Implement in `tui/sparkline.go` as a pure function `Sparkline(data []float64, width int, color lipgloss.Color) string`.

### Layout

Use `lipgloss.JoinHorizontal` and `lipgloss.JoinVertical` to compose panels.
Each view receives `width, height int` and returns `string` — no internal state.
The root model distributes dimensions via `tea.WindowSizeMsg`.

---

## Makefile

```makefile
.PHONY: build run gen clean

# compile the eBPF programs and embed them in the binary
gen:
	go generate ./internal/bpf/...

build: gen
	go build -o bin/xray ./cmd/xray

# requires root for eBPF
run: build
	sudo ./bin/xray --pid $(PID)

clean:
	rm -rf bin/
```

---

## Command-line flags

```
xray --pid <PID>            # inspect a specific process
xray --pid <PID> --fps 10   # refresh rate (default: 5)
xray --pid <PID> --export   # save JSON snapshot on exit ('e' key)
xray --pid <PID> --no-ebpf  # degraded mode: only /proc, no eBPF (for testing)
```

---

## Suggested implementation order for Claude Code

1. `go.mod` + dependencies (bubbletea, lipgloss, libbpfgo)
2. `internal/collector/types.go` — all the types
3. `internal/tui/styles.go` — full palette in Lipgloss
4. `internal/tui/sparkline.go` — reusable braille component
5. `internal/tui/header.go`, `tabbar.go`, `statusbar.go`
6. `internal/tui/model.go` — with mocked data (--no-ebpf mode)
7. Each view in `internal/tui/views/` — start with `overview.go`
8. `internal/collector/fds.go` — /proc polling without eBPF
9. `internal/collector/syscalls.go` — first real eBPF collector
10. The remaining collectors

> Items 1-7 build the full TUI with simulated data, verifiable without root.
> Items 8-10 connect to reality one collector at a time.

---

## Security notes

- eBPF requires `CAP_BPF` or root. The binary must check and print a clear error if it lacks permission.
- In `--no-ebpf` mode, all collectors fall back to reading `/proc` — useful for development.
- Never `panic` in production — collectors must log errors and continue.
