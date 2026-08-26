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
| Build  | Go 1.25+, clang, libbpf-dev (build only) | Single static binary on Linux (`CGO_ENABLED=0`) |
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
│   │   │   ├── cpu.bpf.c          sched_switch → target on-CPU nanoseconds
│   │   │   ├── io.bpf.c           VFS read/write/fsync
│   │   │   ├── network.bpf.c      sock tracepoints + tcp kprobes
│   │   │   ├── threads.bpf.c      sched_switch
│   │   │   ├── memory.bpf.c       mmap/brk/page-fault
│   │   │   ├── heap.bpf.c         libc malloc/free uprobes → lifetime + leak
│   │   │   ├── goalloc.bpf.c      runtime.mallocgc uprobe → Go alloc sites, byte-sampled (#108)
│   │   │   ├── futex.bpf.c        futex wait/wake → lock graph + acquire site
│   │   │   ├── signal.bpf.c       signal_generate → signals with origin (#58)
│   │   │   ├── tls.bpf.c          libssl SSL_write/read uprobes → plaintext (#55)
│   │   │   ├── proc.bpf.c         sched fork/exec/exit → exec lineage subtree (#60)
│   │   │   └── security.bpf.c     PROT_EXEC mmap/mprotect + SELinux AVC (#59)
│   │   ├── available.go           runtime feature flag (build-tag based)
│   │   ├── target.go              target resolver: pid-namespace + cgroup (shared)
│   │   ├── target_spec.go         bpf.Target + cgroup path/level/id helpers (#94)
│   │   ├── cpulist.go             /sys CPU-list parser (build-tag-free, #108)
│   │   ├── goalloc.go             runtime.mallocgc uprobe loader + sampling rate
│   │   ├── goalloc_spec.go        GoAllocDefaultSampleBytes (build-tag-free)
│   │   ├── caps.go                CAP_BPF / CAP_PERFMON detection
│   │   ├── caps_stub.go           non-Linux stub
│   │   ├── caps_test.go
│   │   ├── cpu.go                 on-CPU time tracer (sched_switch)
│   │   ├── syscalls.go            raw_syscalls tracepoint loader
│   │   ├── network.go             sock tracepoints + connection seeding
│   │   ├── io.go                  VFS syscall tracker loader
│   │   ├── memory.go              memory counter loader
│   │   ├── heap.go                libc allocator uprobe loader (#53)
│   │   ├── tls.go                 libssl uprobe loader → TLS plaintext (#55)
│   │   ├── threads.go             sched_switch loader
│   │   ├── futex.go               futex wait/wake loader + contention stacks
│   │   ├── signal.go              signal_generate loader (#58)
│   │   ├── proc.go                sched fork/exec/exit loader → exec lineage (#60)
│   │   ├── security.go            PROT_EXEC + SELinux AVC loader + stack (#59)
│   │   └── *_stub.go              stubs for non-Linux / no-ebpf builds
│   ├── serve/                     headless gRPC server (ptop --serve)
│   │   ├── serve.go               addr parse + privilege boundary + Run
│   │   ├── tls.go                 transport security: TLS/mTLS policy + hot reload (#95)
│   │   ├── hub.go                 fan-in collectors → fan-out to sinks; probe set in the handshake (#112)
│   │   ├── sink.go                Sink iface: gRPC subscriber + JSONL writer
│   │   ├── shed.go                which event a full sink queue gives up (#108)
│   │   ├── registry.go            fixed target vs targets on demand, refcounted (#72)
│   │   ├── stackid.go             wire stack-id namespace + combined resolver (#89)
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
│   ├── collector/                 /proc + eBPF collectors + shared types
│       ├── types.go               public type contracts (see below)
│       ├── set.go                 source-priority selection + lifecycle (Set)
│       ├── probes.go              per-subsystem outcome: active/disabled/failed (#112)
│       ├── bus.go                 single fan-out: Set → N consumers (Feed, #71)
│       ├── shed.go                snapshot vs per-occurrence rate class (#108)
│       ├── source_{linux,darwin}.go  platform source labels (Source*)
│       ├── cpu_proc.go            /proc/<pid>/stat utime+stime
│       ├── cpu_ebpf.go            eBPF on-CPU time → CPU%
│       ├── cpu_rate.go            on-CPU ns → single-core % (build-tag-free)
│       ├── threads_proc.go        /proc/<pid>/task/*/stat + wchan
│       ├── threads_ebpf.go        sched_switch → CPU% real-time
│       ├── mem_proc.go            /proc/<pid>/statm + faults
│       ├── mem_ebpf.go            kprobe + syscall tracepoints
│       ├── heap_ebpf.go           libc malloc/free pairing, or the Go lane (#53)
│       ├── heap_agg.go            call-site ranking + app-frame picking (build-tag-free)
│       ├── futex_agg.go           lock folding + contention-site picking (#89/#107)
│       ├── tls_ebpf.go            libssl uprobe → TLS payload (#55, opt-in --tls)
│       ├── iowait_proc.go         /proc/<pid>/stat field 42
│       ├── io_proc.go             /proc/<pid>/io throughput
│       ├── io_ebpf.go             top files + per-op latency
│       ├── network_ebpf.go        connections + RTT + bytes
│       ├── syscalls_ebpf.go       per-syscall counts + latency
│       ├── futex_ebpf.go          lock graph from futex tracking (#89 call site)
│       ├── proccontext_linux.go   /proc ns + cgroup + uid/gid context (#60)
│       ├── proccontext.go         container-id / cgroup / ns-inode parsers (build-tag-free)
│       ├── proclifecycle_ebpf.go  sched fork/exec/exit → exec lineage subtree (#60)
│       ├── proclifecycle_decode.go  kind/comm/filename decode (build-tag-free)
│       ├── security_ebpf.go       PROT_EXEC mmap/mprotect + LSM denials (#59)
│       ├── security_decode.go     prot/kind/detail decode (build-tag-free)
│       ├── fds.go                 /proc/<pid>/fd + fdinfo + events
│       ├── sockets.go             inode → host:port via /proc/net/*
│       ├── syscall_names.go       syscall id → name table
│       └── *_test.go, *_stub.go
│   └── symbol/                    ELF→symbol resolution (addr → func/file:line, #54)
│       ├── elf.go                 OS-agnostic ELF/gosym core (Module, build-id)
│       ├── dwarf.go               C/C++ file:line from .debug_line
│       ├── lookup.go              name → address (uprobe attach), gosym fallback
│       ├── gopath.go              build-machine source path → import path (#107)
│       ├── perfmap.go             JIT /tmp/perf-<pid>.map frames
│       ├── proc_linux.go          live-pid Symbolizer via /proc/<pid>/maps
│       └── proc_other.go          non-Linux stub
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
    Category  string // "syscall"|"net"|"mem"|"cpu"|"lock"|"io"|"fd"|"sig"|"proc"|"sec"
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

### Rate classes, and why a full queue is not first-come-first-served

Collector values fall into two shapes, and every bounded queue in the pipeline
has to know which it is holding (`pkg/collector/shed.go`,
`internal/serve/shed.go`):

- **Periodic snapshots** — `CpuSample`, `MemStats`, `HeapStats`, `[]ThreadInfo`,
  `[]LockEntry`, … One per collector tick. A handful per second, all told.
- **Per-occurrence events** — `HeapEvent`, `TimelineEvent`, `SignalEvent`,
  `FSEvent`, … One per thing the target did. Unbounded: the Go allocation lane
  can emit hundreds of thousands a second.

Plain drop-when-full lets the second class own the whole queue, and then the
once-a-second `CpuSample` never fits. What comes out the far end is a stream
with **no CPU axis at all**, which reads as an idle process rather than as a
gap — the reported failure in #108, where a 17-second window over a busy Go
service had a CPU distribution of zero at every percentile.

So the last quarter of every queue is reserved for the snapshots: a flood fills
three quarters and stops. Shed values are still counted and still surfaced
(`Subscription.Dropped`, `StreamMeta.dropped`) — a gap is reported, never
hidden. **A new collector value type defaults to the snapshot class**, so
adding one cannot silently starve it; add it to `isPerOccurrenceValue` /
`isPerOccurrence` only if it really is emitted per occurrence.

### A percentage of CPU is a time, so measure the time

The CPU axis used to be a perf_event at 100Hz per CPU whose BPF program
incremented a counter whenever the target happened to be on-CPU; the collector
divided that count by the nominal rate to get a percentage. It disagreed with
`/proc` in both directions, and #108 reported three runs of one binary
measuring 0%, 1% and 19% where `/proc` said 2.5% every time. Two independent
reasons, both structural:

- **The signal was a handful of samples.** A process using 2.5% of a core draws
  2.5 samples a second. A one-second bucket of that is shot noise, and a
  perfectly busy second can legitimately draw ZERO — which reads as an idle
  process, not as a gap. Taking a p95 over a short window then reports the
  maximum of the noise, so the cheap arm of an A/B pair can measure hotter than
  the expensive one and invert the comparison the axis exists for.
- **The nominal rate was not the achieved rate.** In `freq` mode the kernel
  re-derives the sampling period from the count it observes at scheduler ticks,
  and ticks do not run on an idle CPU; after an idle stretch the period inflates
  and the event fires well below the requested rate while the collector keeps
  dividing by the requested rate. Measured on a lightly loaded 10-CPU host:
  80–90Hz per CPU, drifting window to window — a standing undercount, worst on
  exactly the quiet machines where a 2.5% process lives.

`cpu.bpf.c` now brackets the target's slices at `sched_switch` and accumulates
nanoseconds, which is the same quantity `/proc` reports as `utime+stime`, at
nanosecond resolution and with no rate to assume. Measured against
`sum_exec_runtime` over a duty-cycle sweep, it agrees to within about one
percent of the reading at every point from 2.5% to 400% of a core, and where
the truth moves the axis moves with it.

`cmd/ebpfselftest` is the gate: it runs the same pair the report was about —
one workload at a few percent of a core, one at ten times that — and fails if
the axis and `/proc` disagree by more than 15%. The quiet point is the one that
matters, because a full CPU burn is the single case the old sampler got right.

The general rule: sampling estimates *where* time went (which stack, which call
site) and is the only affordable way to get that. It is the wrong instrument
for *how much*, whenever the kernel already accounts the quantity exactly.
Before adding a counter that has to be divided by an assumed rate, check
whether something already counts the thing itself.

### The observer's cost is charged to the target

A uprobe runs on the thread that tripped it, so its cost lands in the TARGET's
own CPU accounting — and ptop's CPU axis samples the target on-CPU, so ptop
then reports it as the target's CPU. That is not a rounding error: measured at
1.1M allocations/s, one stack walk per allocation made the target take **+252%**
longer per unit of work, and the alloc-heavy arm of an A/B pair came out hotter
than the compute-heavy one — inverting the comparison the axis exists for.

Hence `goalloc.bpf.c` samples its stack walk by bytes allocated
(`--heap-sample-bytes`, default 512KB — the same rate Go's own heap profiler
uses). Totals stay exact (a sampled allocation is credited with everything
allocated since the previous one) while per-site attribution becomes an
estimate, and `HeapSnapshot.sample_bytes` says so on the wire. What remains is
the uprobe trap itself, which no amount of sampling removes; `--disable heap`
is the only way to stop paying it.

**The sampling threshold is random, and that is load-bearing.** Allocation
patterns are periodic — a handler allocates the same objects in the same order
every request — and a fixed threshold crossed by a periodic byte stream always
crosses at the same phase of the cycle, so one call site takes every sample and
the rest take none. On a workload alternating a 152-byte allocation with a
1048-byte one, a fixed threshold split the bytes 1.1:1 where the truth is
6.9:1; drawing the threshold uniformly from `[1, 2·rate]` put it at 8:1 (an 89%
share against a true 87%). Any future sampler in this codebase inherits the
same trap.

The rule for any new probe: measure what it costs the target
(`make bench`, `bench/README.md`), and if the cost scales with something the
target does often, sample it rather than shipping a probe that replaces the
program it observes.

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

Collector values reach the model through **one** consumer, `waitBus` (#71),
which reads the model's `collector.Bus` subscription and maps the value to a
message with `busMsg`. Every collector case in `Update` re-arms that same
command — there is no waiter per collector any more, and no case may read a
collector channel directly: a collector hands out one shared channel, so a
direct read would steal events from the gRPC stream and the JSONL export.
`busMsg` demuxes on the value's own type, which is why a `TimelineEvent` from
the fd collector and one from futex are the same message. A value it maps to
nil (a per-allocation `HeapEvent`) is skipped inside the command, so the render
loop never wakes for a payload no panel shows.

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

## Target filter (PID namespaces and cgroups)

Every eBPF program filters through one shared helper, `pid_is_target()` in
`programs/target.bpf.h`, reading a `struct target_filter` the Go loader wrote
(`bpf/target.go`). It supports two ways of naming a target — `bpf.Target`,
built with `TargetPID()` or `TargetCgroup()` (`bpf/target_spec.go`):

**PID mode** resolves pids inside the target's PID namespace via
`bpf_get_ns_current_pid_tgid()` (dev+inode of `/proc/<pid>/ns/pid`). This is
required because `bpf_get_current_pid_tgid()` returns root-namespace pids —
wrong when ptop runs inside a nested namespace (WSL2, Docker, LXC). Never
filter with the bare `bpf_get_current_pid_tgid()` again.

**Cgroup mode** (#94) targets a whole subtree with
`bpf_get_current_ancestor_cgroup_id(level)`: every task inside the target
answers with the target's own cgroup id, forks included, so no pid needs to be
known in advance. The Go side resolves a path or container id to
`(cgroup_id, level)` — the id being the cgroup directory's inode, which is what
the helpers report on kernfs — and refuses level 0, the cgroup root, since that
would trace the whole host. Cgroup v2 only: the helpers report the default
hierarchy's id.

Two caveats worth knowing before extending this:

- **The uprobe collectors are pid-bound.** `heap` (#53) and `tls` (#55) attach
  to a libc/libssl mapped into one process (`resolveLibc`, `resolveLibSSL`,
  `link.UprobeOptions{PID: pid}`), so they take a pid, not a `Target`, and have
  no cgroup-wide equivalent.
- **Cgroup-mode pids are root-namespace pids.** A subtree can span pid
  namespaces, so there is no single namespace to project into; `pid_target_ns()`
  fills `out` from `bpf_get_current_pid_tgid()` in that mode.

Verify both modes with `make ebpf-selftest` → `sudo ./bin/ebpf-selftest`: it
runs one workload and checks the pid filter and the cgroup filter against it
(and then two quieter ones, to check the CPU axis against `/proc` — see the
section on measuring time above)
(the cgroup phase reports SKIP where there is no subtree to target — a cgroup
v1 host, or a cgroup namespace that shows `/` as its own root).

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
ptop --pid <PID> --serve unix:///run/ptop.sock --tui   TUI *and* stream, one set of collectors (#71)
ptop --serve unix:///run/ptop.sock          no --pid: each subscriber names its target (#72)
ptop --serve unix:///run/ptop.sock --serve-max-targets 16   raise the concurrent-target cap (default 8)
ptop --cgroup <path|container-id> --serve <addr>  target a cgroup subtree instead of a PID (#94)
ptop --pid <PID> --serve tcp://127.0.0.1:50051 --serve-insecure   headless over TCP, cleartext (opt-in)
ptop --pid <PID> --serve tcp://<ip>:50051 --serve-tls-cert <crt> --serve-tls-key <key>   over TLS
ptop --pid <PID> ... --serve-tls-client-ca <ca>   also require a client certificate (mTLS)
ptop --pid <PID> --tls       TLS payload metadata (libssl uprobes) — OFF by default (#55)
ptop --pid <PID> --tls-bytes 256   also capture ≤256 plaintext bytes/call (implies --tls)
ptop --pid <PID> --heap-sample-bytes 0   record EVERY Go allocation (exact per site, very expensive)
ptop --pid <PID> --disable heap   drop the one probe that costs the target real time
ptop --pid <PID> --pprof localhost:6060   dev: serve net/http/pprof to profile ptop itself
ptop --version              print version + commit + build date
```

`--pprof <addr>` is a dev-only profiling endpoint: it starts `net/http/pprof`
on `addr` (works in both TUI and `--serve` modes) so you can profile ptop's own
CPU/heap/goroutines — e.g. dogfood with `ptop --pid $(pgrep ptop) --pprof
localhost:6060`, then `go tool pprof http://localhost:6060/debug/pprof/profile`.
It exposes process internals, so bind a loopback addr. Off when the flag is
empty (no server, zero cost).

`--tls` opts into pre-encryption/post-decryption payload capture via uprobes on
the target's libssl (`SSL_write`/`SSL_read`, resolved by symbol — Go targets have
no libssl). It is **stream/export-only** (no live TUI panel): events flow to
`--serve`/`--export`. `--tls` alone captures only metadata (direction, fd, byte
count); the actual **plaintext** is captured only with `--tls-bytes N` (default
0, capped at 4096/call) — it can include credentials/PII, so it's a deliberate
second opt-in with a stderr warning. The `--serve` privilege boundary (unix
0600 / TCP loopback-only) guards the resulting plaintext.

`--cgroup <path|container-id>` targets a cgroup subtree instead of one process
(#94) — see the target-filter section above for the kernel side. It is
`--serve`-only (the TUI is pid-shaped: header, thread table, fd list) and
requires eBPF; `checkTargetFlags` in `cmd/ptop/main.go` rejects the rest.
`bpf.ResolveCgroupSpec` resolves the spec once at startup, so a bad path or an
ambiguous container id fails before any tracer loads and the log says which
cgroup an id matched. `Set.startCgroup` starts only the collectors that can
observe a subtree (syscalls, io, network, futex, cpu, security) — the
`CgroupTargeter` interface in `types.go` is what marks them, and the ones left
out are listed there with the reason. Every subscriber gets a `TargetInfo`
handshake as the first `StreamMeta`, before any event: **the first item on a
stream is now a meta, not an event** — consumers must handle that.

`--serve <addr>` runs headless (no TUI): it builds the same collector `Set` and
streams `streampb.Event`s over the `EventStreamService` gRPC service to any number of
subscribers (fan-out), with bounded per-subscriber buffers that drop-with-counter
under backpressure (surfaced as `StreamMeta`). `addr` is `unix:///path` or
`tcp://host:port`. SIGINT/SIGTERM shuts down and releases collectors. The
collector→`streampb` mapping + server live in `internal/serve`.

`--serve --tui` (#71) adds the TUI as a second consumer of the same collectors:
one `collector.Feed` (a `Set` plus the `Bus` fanning it out), the hub attached
as an inline bus handler and the model as a bus subscription. The TUI runs in
the foreground and quitting it stops the server; `serve.Options.Ready` closes
once the endpoint is bound, so a bad address or certificate is reported before
the alt-screen instead of behind a TUI with nothing behind it. `--export` keeps
its `--serve` meaning there (the event-level JSONL), not the TUI's
state-snapshot one.

**`--serve` with no `--pid`/`--cgroup` serves targets on demand** (#72):
`SubscribeRequest.pid` names the process, a target's collectors start with its
first subscriber and are released when its last one disconnects, so nothing
keeps eBPF loaded for a process nobody watches. `internal/serve/registry.go`
holds both shapes behind one interface — `fixedRegistry` (the command-line
target; it starts and releases nothing) and `onDemandRegistry` (refcounted
`collector.Feed` + `Hub` per pid, capped by `--serve-max-targets`, default 8).
One mutex covers the whole map and is held across collector startup, which
serializes an eBPF load for pid B behind one for pid A; that is deliberate —
it makes a teardown-vs-subscribe race for the same pid impossible.

Three consequences worth knowing:

- **`ResolveStack` takes a pid too.** Kernel stack maps are per-target, so the
  same id means different stacks in different processes. It uses `lookup`, not
  `acquire`: an id for a process nobody is streaming reports `found=false`
  rather than starting collectors to answer, because that stack died with the
  tracer.
- **A fixed-target server validates the pid** instead of ignoring it: `0` (the
  pre-#72 request shape) or its own pid are served, anything else is
  `InvalidArgument` — never the wrong process silently.
- **`--export` and `--tui` need a fixed target.** A JSONL export names one
  target in its header, and the TUI shows one process; both are refused at
  startup in on-demand mode.

The gRPC subscriber and the JSONL writer are interchangeable `Sink`s
(`internal/serve/sink.go`) fed by the hub. `--serve --export` adds the JSONL
sink: `ptop-events-<ts>.jsonl` holds one protojson **`SubscribeResponse` per
line** — the same message a gRPC subscriber receives, in the same order, so one
parser reads either surface. The first line is a meta carrying `TargetInfo`
(without it an export is unattributable: cgroup-mode events have `pid` 0 and
several payloads carry no pid), a meta with `dropped` records a gap where it
happened, and everything else is an `event`
(event-level — distinct from the TUI's state-snapshot `ptop-export-<ts>.jsonl`).

Stack symbolization (#54) rides this surface: heap events carry a
`StackRef{stack_id, build_id}` on the envelope (high-rate events stay small —
they reference a stack, not its frames), and the `ResolveStack(stack_id)` RPC
resolves it to leaf-first `StackFrame`s on demand. The heap collector owns the
stack tracer + `symbol.Symbolizer`, so it backs both — `serve.Run` takes it as
the optional `StackResolver`; a nil resolver simply omits stack refs and reports
`found=false`. `build_id` is the target executable's GNU build-id, a stable
per-process cache key (the same `stack_id` denotes a different stack once the
binary changes).

`LockEntry` rides it too (#89): `uaddr` names a lock only inside the live
process — ASLR and arena reuse move it every run — so each entry also carries
the symbolized `call_site` (`StackFrame`) plus a `stack_id`. That makes
cross-run/deploy lock comparison possible: key on `module+offset` or
`func/file:line`, never on `uaddr`. The kernel counts waits per
`(uaddr, stack_id)` and the collector names the lock by the **dominant** site
of the window, so a mutex taken from many places reports the one actually
serializing it.

Which frame of that stack names the lock is the whole question, and getting it
wrong is worse than not symbolizing at all (#107). The leaf of a futex wait is
the primitive's syscall wrapper — libc's `__lll_lock_wait`, or in a Go binary
`runtime.futex` at one fixed line of `sys_linux_$GOARCH.s`. Every lock in the
process passes through it, so naming locks by that frame gives them all the
same name and folds them into ONE entry, where the bare address at least told
them apart. `pickLockSite` (`futex_agg.go`) therefore walks past the machinery
— loader/libc modules by module, `runtime.`/`internal/runtime/`/`sync.` by name,
since the Go runtime and the application are one module — and stops at the
first application frame. **Finding none, it reports the address and leaves the
symbol fields empty**, so `call_site` is absent on the wire and a consumer
falls back to `uaddr`. That is the normal outcome for a Go target: `sync.Mutex`
parks a goroutine, only the scheduler ever reaches a futex, and `mcall` has
already switched to the g0 stack by then — so there is no application frame to
find.

Source paths get the same treatment (`pkg/symbol/gopath.go`). `.gopclntab`
records the path a file had on the BUILD machine, so `file:line` carried
someone's `$GOROOT` and never matched between two hosts. `Module.Resolve`
rewrites it to the file's import path (`runtime/sys_linux_arm64.s`,
`github.com/x/y/pool.go`), anchored on the directory corroborating the symbol's
package so an inlined frame is not filed under a package it never belonged to.

**Wire stack ids are namespaced by source** (`internal/serve/stackid.go`): each
tracer captures into its own `STACK_TRACE` map, and their ids are independent
counters, so the wire id is `source<<32 | kernel_id` — heap is source 0 (ids
unchanged from before #89), futex is 1, and `0` means "no stack". Pass the id
back verbatim; `CombineStackResolvers` routes it to the tracer that captured
it. Two consequences worth knowing: a new stack-capturing collector must claim
a source constant, and both symbolization paths are **pid-mode only** — in
cgroup mode there is no single memory map to resolve against, so sites stay
unresolved.

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
- Transport security of the stream (#95) lives in `internal/serve/tls.go`:
  `serverCredentials(addr, TLSOptions)` is the single policy gate, resolved
  **before** the listener is created so a bad certificate path fails before
  anything binds. A `tcp://` endpoint must carry TLS (`--serve-tls-cert` +
  `--serve-tls-key`, plus `--serve-tls-client-ca` for
  `RequireAndVerifyClientCert`) or an explicit `--serve-insecure`; a bare
  `tcp://` is refused at startup. Unix sockets take no TLS at all (the flags are
  refused there — file permissions are the boundary), and contradictory
  combinations fail fast rather than silently picking a winner. The material is
  loaded through `tlsReloader`, hooked in as `tls.Config.GetConfigForClient`, so
  a rotated certificate or client CA bundle is adopted on the next handshake
  (fingerprint = size + mtime; a failed reload keeps the last good config and
  warns). Note the trap it documents: a config returned by `GetConfigForClient`
  replaces the outer one wholesale, so it must carry `NextProtos: ["h2"]` or
  every gRPC client fails ALPN. Mind the naming:
  `--tls`/`--tls-bytes` capture the **target's** plaintext, `--serve-tls-*`
  encrypt **ptop's own** stream.
- TLS payload capture (`--tls`/`--tls-bytes`, #55) observes plaintext and is
  **off by default**. It attaches no uprobes unless `--tls` is passed, and emits
  payload bytes only with the additional `--tls-bytes N` (capped 4096/call) —
  never on by default, with a stderr warning when active. The captured plaintext
  rides the same `--serve`/`--export` surface, so the socket/file restrictions
  above are what keep it private. Resolve by symbol (version-drift safe); a Go or
  static target has no libssl, so capture is simply unavailable there.

See [`SECURITY.md`](SECURITY.md) for vulnerability reporting.
