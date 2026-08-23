# ptop — process top

[![CI](https://github.com/trentas/ptop/actions/workflows/ci.yml/badge.svg)](https://github.com/trentas/ptop/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/trentas/ptop?display_name=tag&sort=semver)](https://github.com/trentas/ptop/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/trentas/ptop.svg)](https://pkg.go.dev/github.com/trentas/ptop)
[![Go Report Card](https://goreportcard.com/badge/github.com/trentas/ptop)](https://goreportcard.com/report/github.com/trentas/ptop)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`ptop` is an interactive TUI for deep inspection of processes. Linux is the
rich target (eBPF); macOS runs a reduced "Tier 1" set via libproc + Mach.
Live diagnosis of CPU, syscalls, network, I/O, memory, threads, and file
descriptors — without restarting, instrumenting, or changing a line of code
in the target.

| Tab | Shows | eBPF source |
|---|---|---|
| **F1 Overview** | CPU sparkline, top syscalls, threads, I/O, FDs, network, heap/leak, events | aggregate |
| **F2 Syscalls** | per-call frequency, latency, live event stream | `raw_syscalls:sys_{enter,exit}` |
| **F3 Network**  | TCP/UDP/UNIX connections with state, RTT, Tx/Rx | `sock:inet_sock_set_state` + tcp_sendmsg/cleanup_rbuf kprobes |
| **F4 Threads**  | per-TID state, on-CPU%, lock graph (futex) | `sched:sched_switch` + futex tracepoints |
| **F5 I/O**      | dual throughput, top files, latency histogram | VFS read/write/fsync syscall tracking |
| **F6 FDs**      | live FD table by type, with bytes and active flag | `/proc/<pid>/fd` + open/close events |
| **F7 Timeline** | unified event stream tagged by category | all of the above |

## Snapshot

A real `go test` dump from `internal/tui/dump_test.go`. Every panel matches
what the live binary renders against a real PID.

```text
⬡ ptop │ api-server  PID 1   Go 1.25   RUNNING   15 fds                                                          uptime 00:00  │  18:06:31
  F1 Overview  │  F2 Syscalls  │  F3 Network  │  F4 Threads  │  F5 I/O  │  F6 FD  │  F7 Timeline               q quit · / filter · p pause
┌──────────────────────────────────────────────────────────────────────────────────┐┌──────────────────────────────────────────────────────┐
│ ▸ CPU                                                                            ││ ▸ I/O THROUGHPUT                                     │
│     ⡀⡀⡀ ⡀⡀ ⡄  ⡀ ⡀⡀  ⡀⡀⡄ ⡀⡄⡀⡀⡀⡄⡄⡀⡄⡀  ⡀⡄⡀⡀⡀ ⡀⡄⡀ ⡄⡀⡄⡀⡀   ⡀⡄⡀⡀ ⡀⡀ ⡀⡀        20%││  ⡏⡆⡏⡄⡇ ⡄ ⡟⡟⡏⡄⡟ ⡟⡟⡄⡆⡏ ⡏⡟⡇ ⡆ ⡆⡟⡇⡀⡀⡏⡇⡿⡀⡀⡀⡇  read/s  │
│                                                                         cpu usage││                                          494.2KB     │
│                                                                                  ││⡄⡇⡇⡟⡆  ⡇ ⡆⡀⡏ ⡆⡄⡇⡄⡄⡀⡄⡏⡇⡏⡏⡀⡇⡀⡀⡀⡏⡏⡿⡄⡇⡄⡆⡏⡀ ⡟  write/s│
│                                                                                  ││                                          333.5KB     │
└──────────────────────────────────────────────────────────────────────────────────┘└──────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────────────────────┐┌──────────────────────────────────────────────────────┐
│ ▸ TOP SYSCALLS                                                                   ││ ▸ FILE DESCRIPTORS                                   │
│poll          ████████████████████████████████████████████████████████████     195││file     ████████████████████████████████████████    5│
│read          ███████████████████████████████████████████████████████████░     194││socket   ████████████████████████████████░░░░░░░░    4│
│write         ████████████████████████████████████████████████████████░░░░     184││pipe     ████████████████████████████████░░░░░░░░    4│
│openat        ███████████████████████████████████████████████████████░░░░░     181│└──────────────────────────────────────────────────────┘
│fstat         ██████████████████████████████████████████████░░░░░░░░░░░░░░     151│┌──────────────────────────────────────────────────────┐
│getpid        ████████████████████████████████████████████░░░░░░░░░░░░░░░░     143││ ▸ NETWORK                                            │
│epoll_wait    ███████████████████████████████████████████░░░░░░░░░░░░░░░░░     142││TCP   → 10.0.1.5:5432            WAIT            42ms │
│recvmsg       █████████████████████████████████████████░░░░░░░░░░░░░░░░░░░     135││TCP   ↔ 10.0.0.1:443             ESTABLISHED      8ms │
└──────────────────────────────────────────────────────────────────────────────────┘└──────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────────────────────┐┌──────────────────────────────────────────────────────┐
│ ▸ THREADS                                                                        ││ ▸ EVENT STREAM                                       │
│▶ main        ███████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   34%               ││18:06:31.367 CPU  preempted after 12ms                │
│■ worker-1    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░    -- ⏳ mutex-A    ││18:06:31.367 SYS  futex WAIT mutex-A                  │
│▶ worker-2    ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   18%               ││18:06:31.367 LCK  mutex-A released                    │
│· gc          ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░    -- ⏳ nanosleep  ││18:06:31.367 I/O  write /var/log/app/api.log 512B     │
│■ http-pool   ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░    -- ⏳ epoll_wait ││18:06:31.367  FD  openat → fd=15 /tmp/tmpXXXX         │
└──────────────────────────────────────────────────────────────────────────────────┘└──────────────────────────────────────────────────────┘
 F1-F7 tabs  ·  q quit  ·  p pause  ·  / filter  ·  s snapshot  ·  e export                                       eBPF kernel 6.8 · sampling 100Hz
```

A live recording (vhs script in [`assets/demo.tape`](assets/demo.tape)) will
replace this section soon.

## Requirements

- Linux, kernel **5.8+** (BTF + ring buffer + `CAP_BPF`)
- `amd64` or `arm64`
- For full mode: root, or the binary with `cap_bpf,cap_perfmon+ep`
- For building from source: Go **1.25+**, `clang`, `libbpf-dev`, `bpftool`

## Platform support

macOS has no eBPF and never will — XNU is a different kernel. ptop falls back
to libproc + Mach ("Tier 1") and tells you which tier it started in. Most
panels still carry real data; the ones backed by kernel probes stay empty by
design, and the `?` overlay marks them.

| Subsystem | Linux (eBPF) | macOS (libproc + Mach) |
|---|---|---|
| CPU, threads, memory, heap | full | yes |
| File descriptors + events | full | yes |
| I/O throughput + history | full | yes |
| Network connections | full | yes |
| Syscall counts (aggregate) | full | yes |
| Timeline | full | yes |
| Per-syscall trace (F2) | full | **no public API** |
| Per-file I/O latency (F5) | full | **no public API** |
| Lock graph (F7) | full | **no public API** |
| Signals, exec lineage, LSM events | full | **no public API** |

The three unavailable panels would need DTrace, which SIP restricts, or
kdebug, which is undocumented and root-only. See issue #22 for the research.

## Install

Homebrew (Linux and macOS):

```bash
brew install trentas/tap/ptop
```

Or grab the pre-built Linux binaries (amd64/arm64) published on each tag. The
asset name carries the version, so resolve it first:

```bash
VER=$(curl -fsSL https://api.github.com/repos/trentas/ptop/releases/latest \
      | sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p')
curl -fsSL "https://github.com/trentas/ptop/releases/download/v$VER/ptop-$VER-linux-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/').tar.gz" | tar xz
sudo install ptop /usr/local/bin/
```

Or build from source:

```bash
git clone https://github.com/trentas/ptop.git
cd ptop
make            # gen + vet + test + build-ebpf
```

## Run

```bash
sudo ./bin/ptop --pid <PID>            # full mode (eBPF)
./bin/ptop --pid <PID> --no-ebpf       # /proc-only, no root
sudo ./bin/ptop --pid <PID> --fps 10   # higher render rate
sudo ./bin/ptop --pid <PID> --export   # save JSON snapshot on exit

# Stream events headless (no TUI) over gRPC + JSONL
sudo ./bin/ptop --pid <PID> --serve unix:///run/ptop.sock --export

# Same stream over TCP, encrypted and mutually authenticated (see below)
sudo ./bin/ptop --pid <PID> --serve tcp://10.1.2.3:50051 \
  --serve-tls-cert /etc/ptop/tls/tls.crt \
  --serve-tls-key  /etc/ptop/tls/tls.key \
  --serve-tls-client-ca /etc/ptop/tls/ca.crt

# Target a whole container/pod by cgroup instead of a PID (headless only)
sudo ./bin/ptop --cgroup /kubepods.slice/.../cri-containerd-<id>.scope --serve unix:///run/ptop.sock
sudo ./bin/ptop --cgroup <container-id> --serve unix:///run/ptop.sock

# Capture TLS plaintext around libssl (OFF by default; sensitive — see below)
sudo ./bin/ptop --pid <PID> --tls-bytes 256 --serve unix:///run/ptop.sock --export
```

> **TLS payload capture** (`--tls` / `--tls-bytes N`): uprobes the target's
> libssl (`SSL_write`/`SSL_read`) to record plaintext before encryption / after
> decryption — handy for debugging your own service's encrypted traffic without
> a MITM proxy. It is **off by default**, **stream/export-only** (no live panel),
> and the payload bytes (which may contain credentials/PII) are captured only
> with `--tls-bytes N` (capped at 4096/call). Go and statically-linked targets
> have no libssl, so capture is unavailable there.

### Keys

| Key | Action |
|-----|--------|
| `F1`–`F7` (or `1`–`7`, `Tab`/`Shift+Tab`) | switch tab |
| `p`, `Space` | pause / resume |
| `/` | filter (cycles types in F6) |
| `?` | help overlay (collector status with eBPF/proc/mock source) |
| `s` | one-shot JSON snapshot |
| `e` | toggle continuous JSONL export |
| `q`, `Ctrl+C` | quit |

### Permissions

The recommended setup is to grant capabilities once and run unprivileged:

```bash
sudo setcap cap_bpf,cap_perfmon+ep ./bin/ptop
./bin/ptop --pid <PID>
```

If something is wrong (kernel too old, `unprivileged_bpf_disabled=1`, missing
caps), `ptop` prints an actionable error before opening the TUI:

```
$ ./bin/ptop --pid 1234
error: eBPF not available

Kernel 5.4 detected — ptop requires Linux 5.8+ (BTF + CAP_BPF).
On older kernels, use --no-ebpf (/proc-only mode).
```

## Collector sources

Each subsystem is fed by one of three sources, picked at startup. The `?`
overlay shows which one is active per tab.

| Tab | `--no-ebpf` (Linux) | full mode (eBPF) |
|---|---|---|
| **F1 Overview** | ✅ CPU + Mem + Threads + I/O + FDs | ✅ refined by tracepoints |
| **F2 Syscalls** | ❌ no `/proc` source | ✅ raw_syscalls tracepoint |
| **F3 Network**  | ✅ via `/proc/net/{tcp,udp,unix}` | ✅ + per-conn RTT/bytes |
| **F4 Threads**  | ✅ state + CPU% + wchan | ✅ + futex lock graph |
| **F5 I/O**      | ✅ throughput + iowait | ✅ + top files + histogram |
| **F6 FDs**      | ✅ resolved sockets, bytes, active | ✅ same + active socket detection |
| **F7 Timeline** | partial — only `fd` events | ✅ all categories |

`/proc` sources used in `--no-ebpf`:

- `cpu_proc.go` — `/proc/<pid>/stat` fields 14-15 (utime+stime)
- `threads_proc.go` — `/proc/<pid>/task/*/stat` + `wchan`
- `mem_proc.go` — `/proc/<pid>/statm` + page faults
- `iowait_proc.go` — `/proc/<pid>/stat` field 42 (delayacct_blkio_ticks)
- `io_proc.go` — `/proc/<pid>/io`
- `fds.go` + `sockets.go` — `/proc/<pid>/fd`, `/proc/net/{tcp,tcp6,udp,udp6,unix}`
- `proccontext_linux.go` — `/proc/<pid>/{status,cgroup,ns/*}` → namespace +
  cgroup + uid/gid (the execution/container context, #60). When the target runs
  in a container the derived id (`docker:…`, `containerd:…`, `kubepods:…`, …)
  shows in the header; the full context rides the `--serve`/`--export` stream
  (a periodic `ProcContext`, plus uid/gid/cgroup_id stamped on every event).

eBPF programs in `internal/bpf/programs/`:

- `syscalls.bpf.c` — raw_syscalls/sys_{enter,exit}
- `cpu.bpf.c` — perf_event @ 100Hz/CPU
- `io.bpf.c` — VFS read/write/fsync + filesystem semantics (denials/deletes/renames)
- `network.bpf.c` — sock tracepoints + tcp kprobes + connection errors (RST/retransmit)
- `threads.bpf.c` — sched_switch
- `futex.bpf.c` — wait/wake → lock graph
- `memory.bpf.c` — mmap/brk/page-fault counters
- `heap.bpf.c` — libc malloc/free uprobes → live-heap + lifetime + leak suspects
- `goalloc.bpf.c` — `runtime.mallocgc` uprobe → Go allocation sites (rate + volume)

Any subsystem can be switched off with `--disable <name,...>` — see
[what it costs](#what-it-costs-the-process-it-watches) for why you might.
- `signal.bpf.c` — `signal:signal_generate` → signals delivered, with sender
- `proc.bpf.c` — `sched_process_{fork,exec,exit}` → exec-lineage subtree
- `security.bpf.c` — PROT_EXEC `mmap`/`mprotect` + SELinux AVC denials
- `tls.bpf.c` — libssl `SSL_write`/`SSL_read` uprobes → plaintext (opt-in `--tls`)

### What it costs the process it watches

Measured, not asserted — the harness, methodology and raw data are in
[`bench/`](bench/). ptop used to claim `overhead <0.5%` with nothing behind it;
that claim is gone, and this is what replaced it.

The cost is **not a constant**. ptop's expensive probe fires once per
allocation, so what it costs depends on how often the target allocates:

| target allocation rate | all probes | without the heap probe | heap probe alone |
|---|---|---|---|
| 0 (no allocations) | −4.9% | −4.9% | −4.6% |
| 11k/s | +14.8% | +0.1% | +15.9% |
| 114k/s | +109.9% | +0.2% | +98.1% |
| 1.2M/s | +404.4% | −0.9% | +358.1% |
| 14.4M/s | +3213.9% | +2.3% | +3159.1% |

Target CPU time per unit of work, median of 3 runs, on a 2-core aarch64 host
(kernel 7.0). The noise floor there is **±4.9%**, measured from the row that
allocates nothing — where every cell should read 0% and does not. Nothing
below that magnitude is resolved, which is why the "without the heap probe"
column reads as zero rather than as its literal sign.

Two things follow, and both are actionable:

**Everything except the heap probe is free**, at every rate tested — syscalls,
CPU, threads, I/O, network, locks, signals, security and lifecycle together sit
inside the noise floor. The old `<0.5%` was, by accident, about right for them.

**The heap probe is the entire cost**, and on an allocation-heavy target it is
not a tax, it is a different program. `--disable heap` removes it and keeps
everything else:

```
ptop --pid <PID> --disable heap
```

ptop's own CPU is a separate question with a separate answer: 37–53% of one
core with the heap probe attached, ~1% without.

### Heap: two lanes, picked from the target

`heap.bpf.c` probes the libc allocator. The Go runtime never calls it —
`runtime.mallocgc` carves out of per-P caches backed by mmap'd spans — so a Go
process observed on that lane produces an **empty** call-site axis. Since the
call-site axis is the only part of the heap surface carrying `func`/`file:line`,
that means no link from allocation behaviour back to source for an entire
runtime family.

`goalloc.bpf.c` attaches one uprobe to `runtime.mallocgc`, the single funnel
every Go heap allocation passes through (`newobject`, `makeslice`, `growslice`
and `reflect.unsafe_New` all call it; the size-specialised fast paths are
dispatched from inside it). ptop picks the lane from the target's own
executable — a Go image gets the Go lane, including a cgo build with libc
mapped, since that is where a Go program's allocations actually are.

The lanes measure different things, and the snapshot says which:

| | `lane="libc"` | `lane="go"` |
|---|---|---|
| allocation rate + volume per site | yes | yes |
| `func` / `file:line` per site | via `.symtab` + DWARF | via `.gopclntab` |
| live bytes, lifetime, leak suspects | yes | **no** — `live_measured=false` |

Nothing frees a Go allocation at a point a probe can observe: the GC sweeper
reclaims spans in bulk, asynchronously, naming no object. So the Go lane sets
`live_measured=false` and leaves those fields at 0 to mean *not measured*,
never *measured, and zero* — a consumer diffing two deploys must check the flag
before comparing them.

Symbolization works on stripped release builds (`-ldflags="-s -w"`): `.symtab`
is gone but `.gopclntab` survives, because the runtime needs it for tracebacks.

### Symbolization

A captured stack address becomes `func (file:line)` through whichever of three
sources the module carries, in that order:

| Source | Gives | Present in |
|---|---|---|
| `.gopclntab` | func + file:line | every Go binary, stripped ones included |
| `.symtab` / `.dynsym` | func | C/C++ not built with `-s` |
| DWARF line program | file:line | anything built with `-g` |
| `/tmp/perf-<pid>.map` | func + file:line | JIT runtimes (Node, JVM) |

A module with none of them degrades to `module+0xoffset` rather than guessing.

JIT'd code has no ELF behind it — V8 and the JVM compile into anonymous
executable memory — so an address in no file-backed mapping is resolved from
the runtime's perf map instead. Node writes one under `--perf-basic-prof`, the
JVM under perf-map-agent; it is the same side file `perf(1)` consumes. The
frame's module is reported as `[jit]`, because there is no file to name.

V8 emits the same function once per optimization tier, distinguished only by a
marker: `JS:~hotSmall`, `JS:+hotSmall`, `JS:^hotSmall`. Those are one function
at three addresses. The marker is stripped so they normalize to one identity —
without that, a deploy diff keyed on call-site name would show functions
appearing and vanishing purely because V8 re-tiered them during warm-up.

The map is located through the target's own namespaces: the runtime names the
file with the pid it can see (`perf-1.map` inside a container), and puts it in
its own `/tmp`, so ptop reads `NSpid` from `/proc/<pid>/status` and crosses
into the target's mount namespace via `/proc/<pid>/root`.
DWARF sections are copied in while the file is open and parsed on demand, so a
`Module` still holds no file handle; past a size budget the copy is skipped and
the frame keeps its function name without a line, which is what a
debug-info-heavy C++ image gets instead of hundreds of pinned megabytes.


## Event stream (`--serve`)

The TUI is one consumer of a richer event model. `ptop --pid <PID> --serve
<addr>` runs headless and streams every observation as a typed protobuf `Event`
over gRPC (package `ptop.v1`) to any number of unprivileged subscribers — and,
with `--export`, also to a JSONL file: one protojson `SubscribeResponse` per
line — the same messages, so a file and a live stream parse identically. ptop
holds `CAP_BPF`/`CAP_PERFMON`; subscribers connect with none.

Add `--tui` to watch the process while it streams: the TUI and the subscribers
become consumers of the *same* running collectors, so nobody sees half a stream.
Quitting the TUI stops the server.

```bash
sudo ./bin/ptop --pid <PID> --serve unix:///run/ptop.sock --tui
```

Started **without** `--pid`, the server has no target of its own: each
subscriber names the process it wants in `SubscribeRequest.pid`, that pid's
collectors start with its first subscriber and are released when its last one
disconnects. `--serve-max-targets` (default 8) caps how many run at once, since
each target carries its own eBPF programs.

```bash
sudo ./bin/ptop --serve unix:///run/ptop.sock          # subscribers pick the target
```

### Transport security

The stream carries process internals — heap call sites, filesystem paths and,
with `--tls-bytes`, the target's TLS plaintext. What protects it depends on the
endpoint:

| Endpoint | Protection | Flags |
|---|---|---|
| `unix:///path` | Filesystem: the socket is created `0600` and unlinked on exit | none (TLS flags are refused here) |
| `tcp://host:port` + TLS | Encrypted; the subscriber verifies ptop | `--serve-tls-cert` + `--serve-tls-key` |
| `tcp://host:port` + mTLS | Encrypted **and** only subscribers holding a certificate from your CA are served | the two above + `--serve-tls-client-ca` |
| `tcp://host:port` cleartext | None — anyone who reaches the port reads everything | `--serve-insecure` (explicit opt-in, warns on stderr) |

A `tcp://` endpoint with no certificate and no `--serve-insecure` is **refused
at startup**: cleartext on the wire is a decision, not a default. Binding all
interfaces (`0.0.0.0`/`::`) is refused either way — bind loopback or a specific
interface IP. TLS 1.2 is the floor.

The certificate and the client CA bundle are re-read from disk whenever they
change, so a rotated secret (cert-manager and friends) is picked up on the next
handshake with no restart. If a rotation lands broken — a key caught
half-written — the last good material keeps serving and the reason goes to
stderr, because dropping every subscriber is the worse failure.

> Not to be confused with `--tls`/`--tls-bytes`, which are the opposite
> direction: those capture the *target's* TLS plaintext. `--serve-tls-*`
> encrypts *ptop's own* stream.

### Targeting: one PID, or a whole cgroup

`--pid` names one process. `--cgroup` names a **cgroup subtree** — a container
or a whole pod — and needs no PID at all, so you can attach to a workload
chosen by Kubernetes identity rather than by looking up what it happens to be
running as. The spec is a cgroup path (absolute, or the root-relative form
`/proc/<pid>/cgroup` prints) or a container id, which is resolved by searching
the tree; an ambiguous id is refused rather than guessed. Forks and execs
inside the subtree are covered automatically, because the filter matches the
cgroup, not a process.

Every subscriber is told which mode it is getting, as a `TargetInfo` handshake
in the first `StreamMeta` of the stream, before any event. That matters because
the modes aggregate differently: in cgroup mode `Event.pid` is 0 on aggregate
payloads (there is no single process to name) and any pid inside a payload is a
**root-namespace** pid, since a subtree can span pid namespaces.

Cgroup mode is `--serve` only (the TUI's header, thread table and fd list are
all one process's) and needs eBPF, since the filter runs in the kernel. It
starts a deliberately smaller set of collectors — syscalls, I/O, network,
locks, CPU and security — and the omissions are structural, not unfinished:

| Not available in cgroup mode | Why |
|---|---|
| memory, threads | RSS and thread enumeration come from `/proc/<pid>/statm` and `/proc/<pid>/task` |
| heap (#53), TLS (#55) | uprobes attach into one process's mapped libc/libssl |
| signals (#58), exec lineage (#60) | they filter on a global pid of their own |

Two collectors that do run lose a pid-shaped detail: I/O reports no file paths
(resolving an fd means reading `/proc/<pid>/fd`) and security call sites stay
in hex (symbolization reads one process's memory map).

Beyond the seven TUI tabs, the stream carries the full process-behavior surface
(each event tagged by `category`, with `uid`/`gid`/`cgroup_id` stamped on every
envelope):

| Category | Event | What it captures |
|---|---|---|
| `MEMORY` | `HeapEvent` / `HeapSnapshot` | allocations by call site (symbolized). libc lane: malloc/free paired → live-heap, lifetime, leak suspects. Go lane: rate + volume, `live_measured=false` |
| `NETWORK` | `NetErrorEvent` | TCP failures: connection refused, reset, retransmits |
| `NETWORK` | `TLSPayloadEvent` | pre-encryption / post-decryption plaintext (opt-in `--tls`) |
| `IO` | `FSEvent` | filesystem semantics: permission denials, deletes, renames (real paths) |
| `SIGNAL` | `SignalEvent` | signals delivered to the target, with the sending process |
| `PROCESS` | `ProcContext` | namespace + cgroup + uid/gid (container/execution context) |
| `PROCESS` | `ProcLifecycleEvent` | exec lineage: fork/exec/exit across the descendant subtree |
| `SECURITY` | `SecurityEvent` | runtime PROT_EXEC mappings (JIT/RWX), SELinux LSM denials |

High-rate events reference a captured stack by id; the `ResolveStack` RPC
symbolizes it on demand (`addr → func (file:line)`, build-id keyed).

Some `Event` payloads, shown unwrapped for readability — on the wire and in the
JSONL each one arrives inside a `SubscribeResponse` (`{"event":{…}}`), which is
also where the target handshake and the drop notices live:

```jsonl
{"tsUnixNano":"…","pid":4242,"category":"CATEGORY_PROCESS","uid":1000,"gid":1000,"cgroupId":"2817","procContext":{"pidNs":"4026532630","cgroup":"/docker/3127f7e31dab…","container":"docker:3127f7e31dab"}}
{"tsUnixNano":"…","pid":4242,"category":"CATEGORY_PROCESS","procLifecycle":{"kind":"exec","pid":4310,"comm":"sh","filename":"/usr/bin/sh"}}
{"tsUnixNano":"…","pid":4242,"category":"CATEGORY_NETWORK","netError":{"kind":"refused","remote":"10.0.0.9:5432"}}
{"tsUnixNano":"…","pid":4242,"category":"CATEGORY_SIGNAL","tid":4242,"signal":{"signal":"SIGPIPE","signo":13,"code":128,"targetTid":4242}}
{"tsUnixNano":"…","pid":4242,"category":"CATEGORY_SECURITY","security":{"kind":"exec-map","op":"mprotect","prot":5,"callSite":{"func":"jit_emit"}}}
```

The schema lives in [`proto/event.proto`](proto/event.proto); collectors and
their source-priority selection are shared verbatim between the TUI and the
server, so both see identical data.

## Architecture

```
ptop/
├── cmd/ptop/                 entrypoint
├── proto/                    event-stream schema (package ptop.v1)
├── internal/
│   ├── bpf/                  eBPF programs + loader (build tag `ebpf`)
│   ├── serve/                headless gRPC server (ptop --serve)
│   └── tui/                  Bubbletea + Lipgloss views
├── pkg/                      importable API surface
│   ├── collector/            /proc + eBPF collectors + shared types
│   ├── streampb/             generated gRPC / protobuf bindings
│   └── symbol/               ELF → symbol resolution (addr → func/file:line)
└── assets/                   visual references + vhs script
```

See [`CLAUDE.md`](CLAUDE.md) for the full implementation guide, type
contracts, and conventions.

## Development

```bash
make            # gen + vet + test (both lanes) + build-ebpf — default goal
make test       # go test -race ./...
make vet        # vet in both modes (default + tags=ebpf)
make clean      # rm -rf bin/ + *.bpf.o
make lint       # golangci-lint (must be installed)
```

CI runs both lanes (`-tags=ebpf` and default) on `ubuntu-latest`. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the PR flow and commit conventions.

## License

MIT. See [`LICENSE`](LICENSE).
