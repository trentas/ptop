# ptop — implementation guide

Interactive TUI for deep inspection of processes.
Linux is the rich target (eBPF + /proc); macOS is a Tier 1 port via
libproc + Mach with a reduced feature set (see the `*_darwin.go` files
under `pkg/collector/` and issue #22).

This file documents the implementation: tech stack, project layout, type
contracts, and the conventions every collector and view follows.

If something here drifts from reality, the code wins. Update this file.

---

## Stack

| Layer  | Technology | Reason |
|--------|-----------|--------|
| TUI    | [Bubbletea](https://github.com/charmbracelet/bubbletea) + [Lipgloss](https://github.com/charmbracelet/lipgloss) | Mature, composable, mouse support |
| eBPF   | [cilium/ebpf](https://github.com/cilium/ebpf) | Pure-Go, no libbpf.so needed at runtime |
| Build  | Go 1.22+, clang, libbpf-dev (build only) | Single static binary on Linux (`CGO_ENABLED=0`) |
| eBPF C | clang `-target bpf` → `.bpf.o` → `go:embed` | See `Makefile` |
| macOS  | libproc + Mach via cgo (darwin-only build tag) | The only public path for per-process info on macOS |

> Don't introduce a CLI framework — `flag` is sufficient.
> Don't add a logging library — `fmt.Fprintln(os.Stderr, ...)` is enough.
> CGo is gated to `//go:build darwin` for libproc/Mach. The Linux binary
> stays `CGO_ENABLED=0` and statically linked; do not pull cgo into any
> file that compiles on linux.

---

## Visual reference

`assets/mockup.jsx` contains the React prototype with all tabs implemented and
simulated data. **Each Go view must faithfully reproduce the layout of the
corresponding mockup.** Use it as the authoritative visual spec — if there's
any doubt about layout, the mockup wins.

`assets/screenshot-overview.txt` is a captured F1 dump used as a regression
fixture in `internal/tui/dump_test.go`.

Color palette (defined in `internal/tui/styles.go`):

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
ptop/
├── CLAUDE.md, README.md, CONTRIBUTING.md, SECURITY.md, LICENSE
├── go.mod, go.sum
├── Makefile, .goreleaser.yaml
├── buf.yaml, buf.gen.yaml         protobuf codegen config (`make proto`)
├── proto/                         event stream schema (pkg ptop.v1)
│   ├── event.proto                unified Event + payloads
│   └── service.proto              EventStream gRPC service
├── cmd/ptop/main.go               entrypoint: parse flags, start model
├── cmd/ebpfselftest/              root-only eBPF self-diagnostic
├── internal/
│   ├── bpf/                       eBPF programs + loader (build tag `ebpf`)
│   │   ├── programs/              .bpf.c sources, compiled by `make gen`
│   │   │   ├── target.bpf.h       shared pid-namespace target filter
│   │   │   ├── syscalls.bpf.c     raw_syscalls/sys_{enter,exit}
│   │   │   ├── cpu.bpf.c          perf_event @ 100Hz/CPU
│   │   │   ├── io.bpf.c           VFS read/write/fsync
│   │   │   ├── network.bpf.c      sock tracepoints + tcp kprobes
│   │   │   ├── threads.bpf.c      sched_switch
│   │   │   ├── memory.bpf.c       mmap/brk/page-fault
│   │   │   └── futex.bpf.c        futex wait/wake → lock graph
│   │   ├── available.go           runtime feature flag (build-tag based)
│   │   ├── target.go              pid-namespace target resolver (shared)
│   │   ├── caps.go                CAP_BPF / CAP_PERFMON detection
│   │   ├── caps_stub.go           non-Linux stub
│   │   ├── caps_test.go
│   │   ├── cpu.go                 perf_event tracer
│   │   ├── syscalls.go            raw_syscalls tracepoint loader
│   │   ├── network.go             sock tracepoints + connection seeding
│   │   ├── io.go                  VFS syscall tracker loader
│   │   ├── memory.go              memory counter loader
│   │   ├── threads.go             sched_switch loader
│   │   ├── futex.go               futex wait/wake loader
│   │   └── *_stub.go              stubs for non-Linux / no-ebpf builds
│   ├── serve/                     headless gRPC server (ptop --serve)
│   │   ├── serve.go               addr parse + privilege boundary + Run
│   │   ├── hub.go                 fan-in collectors → fan-out subscribers
│   │   ├── service.go             EventStream gRPC service impl
│   │   └── mapper.go              collector value → streampb.Event
│   └── tui/                       Bubbletea + Lipgloss
│       ├── model.go               root model: state + msg routing
│       ├── keys.go                keybindings F1-F7, q, p, /, s, e
│       ├── styles.go              palette + Lipgloss styles
│       ├── sparkline.go           braille sparkline component
│       ├── format.go              human-readable formatters (bytes, ns, ...)
│       ├── panel.go               titled box layout helper
│       ├── panels.go              reusable inner panel renderers
│       ├── header.go              top bar (badges + uptime + clock)
│       ├── tabbar.go              F1-F7 tab bar
│       ├── statusbar.go           footer with keybindings
│       ├── help.go                ? overlay (collector source visibility)
│       ├── snapshot.go            JSON / JSONL export
│       ├── view_overview.go       F1
│       ├── view_syscalls.go       F2
│       ├── view_network.go        F3
│       ├── view_threads.go        F4
│       ├── view_io.go             F5
│       ├── view_fd.go             F6
│       ├── view_timeline.go       F7
│       └── *_test.go              dump test, model test, snapshot test
├── pkg/                           public API surface (importable externally)
│   ├── streampb/                  generated gRPC/proto bindings (pkg ptop.v1)
│   │   ├── event.pb.go            Event schema (generated)
│   │   ├── service.pb.go          Subscribe messages (generated)
│   │   ├── service_grpc.pb.go     EventStream service (generated)
│   │   └── doc.go                 package doc
│   └── collector/                 /proc + eBPF collectors + shared types
│       ├── types.go               public type contracts (see below)
│       ├── set.go                 source-priority selection + lifecycle (Set)
│       ├── source_{linux,darwin}.go  platform source labels (Source*)
│       ├── cpu_proc.go            /proc/<pid>/stat utime+stime
│       ├── cpu_ebpf.go            eBPF perf_event sampling
│       ├── threads_proc.go        /proc/<pid>/task/*/stat + wchan
│       ├── threads_ebpf.go        sched_switch → CPU% real-time
│       ├── mem_proc.go            /proc/<pid>/statm + faults
│       ├── mem_ebpf.go            kprobe + syscall tracepoints
│       ├── iowait_proc.go         /proc/<pid>/stat field 42
│       ├── io_proc.go             /proc/<pid>/io throughput
│       ├── io_ebpf.go             top files + per-op latency
│       ├── network_ebpf.go        connections + RTT + bytes
│       ├── syscalls_ebpf.go       per-syscall counts + latency
│       ├── futex_ebpf.go          lock graph from futex tracking
│       ├── fds.go                 /proc/<pid>/fd + fdinfo + events
│       ├── sockets.go             inode → host:port via /proc/net/*
│       ├── syscall_names.go       syscall id → name table
│       └── *_test.go, *_stub.go
└── assets/
    ├── mockup.jsx                 authoritative visual spec
    └── screenshot-overview.txt    regression fixture
```

> View files live flat under `internal/tui/` (`view_*.go`), not under a
> `views/` subpackage — they share unexported helpers with the model.

> `collector` lives under `pkg/` (not `internal/`) so external programs can
> import it — both as in-process embedders and as the foundation for the
> headless gRPC stream (#51). Its emitted types are therefore a public API
> surface: keep them deliberate. It may still import `internal/bpf` (same
> module). The `tui` is a pure consumer of `collector` — no shared mutable
> state, no reverse dependency.

---

## Core data types (`pkg/collector/types.go`)

All collectors publish typed values to a `chan interface{}` consumed by the
model. The exact struct shapes are the source of truth — refer to `types.go`.
Representative samples:

```go
type CpuSample struct {
    UsagePct  float64
    Timestamp time.Time
}

type SyscallEvent struct {
    Name      string
    Count     uint64
    LatencyNs uint64
}

type NetConn struct {
    FD        int
    Type      string // "TCP" | "UDP" | "UNIX"
    Remote    string
    State     string // "ESTABLISHED" | "WAIT" | ...
    LatencyMs float64
    TxBytes   uint64
    RxBytes   uint64
}

type IOEvent struct {
    Op        string // "read" | "write" | "fsync" | "openat"
    Path      string
    Bytes     uint64
    LatencyMs float64
    FD        int
}

type FDEntry struct {
    FD     int
    Type   string // "file" | "socket" | "pipe" | "epoll" | "timer"
    Desc   string
    Flags  string
    Bytes  uint64
    AgeMs  int64
    Active bool
}

type ThreadInfo struct {
    TID     int
    Name    string
    State   string // "running" | "blocked" | "sleeping"
    CPUPct  float64
    Waiting string
}

type TimelineEvent struct {
    Timestamp time.Time
    Category  string // "syscall"|"net"|"mem"|"cpu"|"lock"|"io"|"fd"
    Message   string
}
```

---

## Collector contract

Every collector implements:

```go
type Collector interface {
    Start(pid int) error
    Stop()
    Subscribe() <-chan interface{} // sends one of the typed structs above
}
```

- `Start` returns an error if the data source isn't available (no `/proc`,
  missing `CAP_BPF`, kernel too old). The model logs the warning and falls
  back to either another source for the same subsystem or simulated data.
- `Stop` must be idempotent and safe even if `Start` failed.
- `Subscribe` may return `nil` for stub collectors — model handles that.
- Collectors must **never panic in steady state**. Errors go to stderr
  and the goroutine continues (or exits cleanly via `Stop`).

### Source priority per subsystem

For each subsystem the model tries sources in this order, taking the first
that succeeds:

1. eBPF collector (richest data, requires `-tags=ebpf` + caps)
2. `/proc` collector (degraded but real)
3. simulated/mocked data (only if both above fail — clearly marked in `?` overlay)

The `?` help overlay surfaces the active source per subsystem (`real via eBPF`,
`real via /proc`, or `mock`). Never lie about the source — users debug with
this.

---

## TUI conventions

### Model

The root `Model` is the single source of state. View functions are pure: they
take `m Model, width, height int` and return `string`. No mutation, no
internal state.

Messages flow through `Update(msg tea.Msg)`:
- `TickMsg`: render tick (FPS-bounded)
- `CpuMsg`, `SyscallMsg`, `NetMsg`, `IOMsg`, `FDMsg`, `ThreadMsg`,
  `TimelineMsg`: collector publish
- `tea.WindowSizeMsg`: layout reflow
- `tea.KeyMsg`: tab switch / pause / filter / snapshot / quit

### Layout

Use `lipgloss.JoinHorizontal` / `lipgloss.JoinVertical` to compose panels.
Every panel uses `internal/tui/panel.go` for its titled box. The root model
distributes dimensions via `tea.WindowSizeMsg` — never query the terminal
directly.

### Sparklines

Unicode braille (`⣀⣄⣆⣇⡇⡏⡟⡿`, 8-level per column).
`Sparkline(data []float64, width int, color lipgloss.Color) string` is pure
and reused across views.

### Width discipline

The header and status bar must **never overflow the terminal width** — the
line wraps and the rest of the TUI flips upside down. `header.go` shows the
priority-based segment dropping pattern: copy it for any new dynamic strip.

---

## PID namespaces

eBPF programs filter the target process via `bpf_get_ns_current_pid_tgid()`,
resolving pids inside the target's PID namespace (dev+inode of
`/proc/<pid>/ns/pid`, written by the Go loader into `struct target_filter`).
This is required because `bpf_get_current_pid_tgid()` returns root-namespace
pids — wrong when ptop runs inside a nested namespace (WSL2, Docker, LXC).
The shared logic lives in `programs/target.bpf.h` and `bpf/target.go`; never
filter with the bare `bpf_get_current_pid_tgid()` again. Verify with
`make ebpf-selftest` → `sudo ./bin/ebpf-selftest`.

## Build tags

- `//go:build linux && ebpf` — real eBPF code (loader + program objects)
- `//go:build !linux || !ebpf` — stubs that fail `Start` cleanly

This split lets the project `go vet` and `go test` on any host without the
eBPF toolchain. The `bpf.Available` const reflects which lane was compiled.

---

## Command-line flags (`cmd/ptop/main.go`)

```
ptop --pid <PID>            inspect a specific process
ptop --pid <PID> --fps 10   render rate (default: 5)
ptop --pid <PID> --export   save JSON snapshot on exit (also bound to 'e')
ptop --pid <PID> --no-ebpf  degraded mode: /proc only, no eBPF
ptop --pid <PID> --serve unix:///run/ptop.sock   headless: stream events over gRPC, no TUI
ptop --pid <PID> --serve tcp://127.0.0.1:50051   headless over TCP (loopback)
ptop --version              print version + commit + build date
```

`--serve <addr>` runs headless (no TUI): it builds the same collector `Set` and
streams `streampb.Event`s over the `EventStreamService` gRPC service to any number of
subscribers (fan-out), with bounded per-subscriber buffers that drop-with-counter
under backpressure (surfaced as `StreamMeta`). `addr` is `unix:///path` or
`tcp://host:port`. SIGINT/SIGTERM shuts down and releases collectors. The
collector→`streampb` mapping + server live in `internal/serve`.

Version metadata is injected via `-ldflags` at release time
(`main.version`, `main.commit`, `main.buildDate`). In dev they stay as
`"dev"`/`"none"`/`"unknown"`.

---

## Security notes

- eBPF requires `CAP_BPF + CAP_PERFMON` (or root). `bpf.GetCapStatus()` /
  `Diagnose()` produce a structured error before the TUI starts — never
  silently fall through to a non-functional state.
- In `--no-ebpf` mode, all collectors fall back to `/proc` — useful when
  granting caps isn't acceptable.
- Never `panic` in production paths — collectors log to stderr and continue.
- The binary is built with `CGO_ENABLED=0` — no dynamic linking, no surprise
  shared-library footprint.
- `--serve` is the privilege boundary: ptop holds `CAP_BPF`/`CAP_PERFMON` and
  publishes events; subscribers connect with none. The unix socket is created
  `0600` (owner-only) and removed on exit. For TCP, binding all interfaces
  (`0.0.0.0`/`::`) is refused — the stream exposes process internals, so bind
  loopback or a specific interface IP.

See [`SECURITY.md`](SECURITY.md) for vulnerability reporting.
