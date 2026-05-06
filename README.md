# ptop — process top

[![CI](https://github.com/trentas/ptop/actions/workflows/ci.yml/badge.svg)](https://github.com/trentas/ptop/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/trentas/ptop?display_name=tag&sort=semver)](https://github.com/trentas/ptop/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/trentas/ptop.svg)](https://pkg.go.dev/github.com/trentas/ptop)
[![Go Report Card](https://goreportcard.com/badge/github.com/trentas/ptop)](https://goreportcard.com/report/github.com/trentas/ptop)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`ptop` is an interactive TUI for deep inspection of Linux processes via eBPF.
Live diagnosis of CPU, syscalls, network, I/O, memory, threads, and file
descriptors — without restarting, instrumenting, or changing a line of code
in the target.

| Tab | Shows | eBPF source |
|---|---|---|
| **F1 Overview** | CPU sparkline, top syscalls, threads, I/O, FDs, network, events | aggregate |
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
⬡ ptop │ api-server  PID 1   Go 1.22   RUNNING   15 fds                                                          uptime 00:00  │  18:06:31
  F1 Overview  │  F2 Syscalls  │  F3 Network  │  F4 Threads  │  F5 I/O  │  F6 FD  │  F7 Timeline               q quit · / filter · p pause
┌──────────────────────────────────────────────────────────────────────────────────┐┌──────────────────────────────────────────────────────┐
│ ▸ CPU                                                                            ││ ▸ I/O THROUGHPUT                                     │
│           ⡀⡀⡀ ⡀⡀ ⡄  ⡀ ⡀⡀  ⡀⡀⡄ ⡀⡄⡀⡀⡀⡄⡄⡀⡄⡀  ⡀⡄⡀⡀⡀ ⡀⡄⡀ ⡄⡀⡄⡀⡀   ⡀⡄⡀⡀ ⡀⡀ ⡀⡀        20%││  ⡏⡆⡏⡄⡇ ⡄ ⡟⡟⡏⡄⡟ ⡟⡟⡄⡆⡏ ⡏⡟⡇ ⡆ ⡆⡟⡇⡀⡀⡏⡇⡿⡀⡀⡀⡇  read/s      │
│                                                                         cpu usage││                                          494.2KB     │
│                                                                                  ││⡄⡇⡇⡟⡆  ⡇ ⡆⡀⡏ ⡆⡄⡇⡄⡄⡀⡄⡏⡇⡏⡏⡀⡇⡀⡀⡀⡏⡏⡿⡄⡇⡄⡆⡏⡀ ⡟  write/s     │
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
 F1-F7 tabs  ·  q quit  ·  p pause  ·  / filter  ·  s snapshot  ·  e export                          eBPF kernel 6.8 · sampling 100Hz · overhead <0.5%
```

A live recording (vhs script in [`assets/demo.tape`](assets/demo.tape)) will
replace this section soon.

## Requirements

- Linux, kernel **5.8+** (BTF + ring buffer + `CAP_BPF`)
- `amd64` or `arm64`
- For full mode: root, or the binary with `cap_bpf,cap_perfmon+ep`
- For building from source: Go **1.22+**, `clang`, `libbpf-dev`, `bpftool`

## Install

Pre-built Linux binaries (amd64/arm64) are published on each tag:

```bash
curl -L https://github.com/trentas/ptop/releases/latest/download/ptop-linux-amd64.tar.gz | tar xz
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
```

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

eBPF programs in `internal/bpf/programs/`:

- `syscalls.bpf.c` — raw_syscalls/sys_{enter,exit}
- `cpu.bpf.c` — perf_event @ 100Hz/CPU
- `io.bpf.c` — VFS read/write/fsync
- `network.bpf.c` — sock tracepoints + tcp kprobes
- `threads.bpf.c` — sched_switch
- `futex.bpf.c` — wait/wake → lock graph
- `memory.bpf.c` — mmap/brk/page-fault counters

## Architecture

```
ptop/
├── cmd/ptop/                 entrypoint
├── internal/
│   ├── bpf/                  eBPF programs + loader (build tag `ebpf`)
│   ├── collector/            /proc + eBPF collectors + shared types
│   └── tui/                  Bubbletea + Lipgloss views
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
