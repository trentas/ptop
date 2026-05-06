# xray

Interactive TUI for deep inspection of Linux processes via eBPF.
Live diagnosis of CPU, syscalls, network, I/O, memory, threads, and file
descriptors — without restarting, without instrumenting, without changing
a line of code in the target.

```
⬡ xray │ api-server  PID 1   Go 1.22   RUNNING   15 fds                                                          uptime 00:00  │  18:06:31
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

> The frame above is a real dump from `go test` in `--no-ebpf` mode. Runs in any modern terminal.
> The React version of the mockup lives in [`assets/mockup.jsx`](assets/mockup.jsx) — authoritative visual reference.

---

## Quickstart

### Prerequisites

- **macOS / dev (no eBPF):** Go 1.22+
- **Linux (full mode):** Go 1.22+, kernel 5.8+ (BTF + ring buffer), `clang`, `bpftool`, `libbpf-dev`, root or `CAP_BPF`

### Build

```bash
git clone git@github.com:trentas/xray.git
cd xray

# default — no eBPF, any OS (TUI + /proc collectors)
make build

# with embedded eBPF — Linux only, requires libbpf
make build-ebpf
```

### Run

```bash
# /proc-only mode (Linux + macOS dev)
./bin/xray --pid 1234 --no-ebpf

# full mode (Linux with sudo)
sudo ./bin/xray --pid 1234

# custom refresh rate (default: 5fps render, sim every 700ms)
sudo ./bin/xray --pid 1234 --fps 10

# save JSON snapshot on exit
sudo ./bin/xray --pid 1234 --export
```

### Navigation

| Key | Action |
|-------|------|
| `F1`–`F7` | Switch tab |
| `Tab` / `Shift+Tab` | Next / previous tab |
| `1`–`7` | Tab shortcut (alternative to F1-F7) |
| `p`, `Space` | Pause / resume simulation |
| `/` | Filter (cycles types in F6) |
| `q`, `Ctrl+C` | Quit |
| `?` | Help overlay (collector status with eBPF/proc/mock source) |
| `s` | One-shot JSON snapshot |
| `e` | Toggle continuous export (JSONL) |

### Verifying eBPF loaded

The help overlay (`?`) shows each collector with its source: `cpu ● real via eBPF`, `cpu ● real via /proc`, or `cpu ○ mock`.

If an eBPF collector failed to start, the error appears on **stderr** before the TUI comes up:

```
$ sudo ./bin/xray --pid 1234
warning: eBPF cpu collector unavailable: perf_event_open: operation not permitted
```

Common: `operation not permitted` = missing `CAP_BPF` + `CAP_PERFMON` or kernel with `unprivileged_bpf_disabled=1`.

Extra kernel-side check (Linux):

```bash
# List eBPF programs loaded by the kernel
sudo bpftool prog list | grep -E 'tracepoint|perf_event' | tail
```

When xray is running with eBPF active, you should see `handle_sys_enter` / `handle_sys_exit` (#9) and `handle_perf_event` (#10).

---

## Collector status

Each tab can be fed by 3 different sources, depending on the mode. ✅ = real, ⚠️ = planned, ❌ = no source in that mode.

| Tab | macOS dev | `--no-ebpf` (Linux) | eBPF (`-tags=ebpf` + sudo) |
|---|---|---|---|
| **F1 Overview**     | mock | ✅ CPU + Mem + Threads + I/O + FDs | ⚠️ refined by #9-#14 |
| **F2 Syscalls**     | mock | ❌ no `/proc` source | ⚠️ #9 (raw_syscalls tracepoint) |
| **F3 Network**      | mock | ✅ connections via `/proc/net/{tcp,udp,unix}` | ⚠️ #12 (per-peer latency) |
| **F4 Threads**      | mock | ✅ state + CPU% + waiting (wchan) | ⚠️ #13 (off-CPU + lock graph) |
| **F5 I/O**          | mock | ✅ throughput (`/proc/<pid>/io`) + iowait (field 42) | ⚠️ #11 (top files + per-op latency) |
| **F6 FDs**          | mock | ✅ complete: resolved sockets, bytes, active, events | ⚠️ #11 (correct active for sockets) |
| **F7 Timeline**     | mock | partial — only the `fd` category has a real source | ⚠️ all via #9-#14 |

### Implemented sources

- `internal/collector/cpu_proc.go` — `/proc/<pid>/stat` fields 14-15 (utime+stime)
- `internal/collector/threads_proc.go` — `/proc/<pid>/task/*/stat` + `wchan`
- `internal/collector/mem_proc.go` — `/proc/<pid>/statm` + page faults
- `internal/collector/iowait_proc.go` — `/proc/<pid>/stat` field 42 (delayacct_blkio_ticks)
- `internal/collector/io_proc.go` — `/proc/<pid>/io` (read_bytes/write_bytes/syscr/syscw)
- `internal/collector/fds.go` + `sockets.go` — `/proc/<pid>/fd`, `/proc/<pid>/fdinfo`, `/proc/net/{tcp,tcp6,udp,udp6,unix}`

### Known limitations (`--no-ebpf` mode)

- **CPU%**: clkTck hardcoded at 100Hz (default x86/x86_64). ARM with `CONFIG_HZ=250` reports 2.5× lower.
- **F2 Syscalls** empty: there is no per-syscall counter in `/proc`.
- **F7 Timeline** partial: only FD events (open/close/dup) in `/proc` mode. Other categories require eBPF tracepoints.
- **CAP_BPF / SIP**: see [issue #19](https://github.com/trentas/xray/issues/19).

---

## Architecture

```
xray/
├── cmd/xray/                  entrypoint: parse flags, start model
├── internal/
│   ├── bpf/                   eBPF programs + loader (tag `ebpf`)
│   ├── collector/             /proc collectors + shared types
│   │   ├── types.go           CpuSample, IOWaitSample, FDEntry, ...
│   │   ├── cpu_proc.go        /proc/<pid>/stat utime+stime
│   │   ├── threads_proc.go    /proc/<pid>/task/*/stat + wchan
│   │   ├── mem_proc.go        /proc/<pid>/statm + faults
│   │   ├── iowait_proc.go     field 42 (block I/O wait)
│   │   ├── io_proc.go         /proc/<pid>/io (throughput + ops)
│   │   ├── fds.go             /proc/<pid>/fd + fdinfo + open/close events
│   │   └── sockets.go         inode resolution via /proc/net/*
│   └── tui/                   Bubbletea + Lipgloss
│       ├── model.go           global state, msg routing
│       ├── keys.go            keybindings F1-F7, q, p, /, s, e
│       ├── styles.go          palette + Lipgloss styles
│       ├── sparkline.go       braille sparklines
│       ├── panel.go           titled box (layout helper)
│       ├── header.go          top bar (badges + uptime + clock)
│       ├── tabbar.go          F1-F7
│       ├── statusbar.go       footer with keybindings
│       ├── panels.go          reusable renderers
│       └── view_*.go          7 views (overview + syscalls + network + ...)
└── assets/
    ├── mockup.jsx                   authoritative visual spec in React
    └── screenshot-overview.txt      F1 dump in --no-ebpf
```

See [`CLAUDE.md`](CLAUDE.md) for the full implementation spec and type reference.

---

## Roadmap

**Closed** (PRs #23-#29):
- ✅ Full TUI across all 7 tabs
- ✅ `/proc` collectors for CPU, threads, memory, I/O wait, throughput, FDs
- ✅ Socket inode resolution (TCP/UDP/UNIX)
- ✅ FD open/close/dup events
- ✅ CI (vet + race + build, default + tags=ebpf)
- ✅ Build tags isolating eBPF code

**Next block — quality of life:**
- [#15](https://github.com/trentas/xray/issues/15) snapshot/JSON export
- [#16](https://github.com/trentas/xray/issues/16) `/` input filter + `?` help overlay
- [#19](https://github.com/trentas/xray/issues/19) capabilities UX (CAP_BPF/PERFMON)
- [#20](https://github.com/trentas/xray/issues/20) release tooling

**Next block — eBPF:**
- [#9](https://github.com/trentas/xray/issues/9) syscalls.bpf.c + loader (raw_syscalls tracepoint)
- [#10](https://github.com/trentas/xray/issues/10) CPU sampling via perf_event
- [#11](https://github.com/trentas/xray/issues/11) block I/O tracepoints (top files + latency)
- [#12](https://github.com/trentas/xray/issues/12) network sock tracepoints
- [#13](https://github.com/trentas/xray/issues/13) sched tracepoints + off-CPU profiling
- [#14](https://github.com/trentas/xray/issues/14) memory tracepoints

**Future ports** (non-blocking, OS-specific):
- [#21](https://github.com/trentas/xray/issues/21) Windows 11 via ETW (eBPF for Windows is networking-only)
- [#22](https://github.com/trentas/xray/issues/22) macOS via libproc + Mach (DTrace blocked by SIP in OSS)

---

## Development

```bash
make test            # go test -race ./...
make vet             # vet in both modes (default + tags=ebpf)
make clean           # rm -rf bin/
make lint            # golangci-lint (must be installed)
```

### Linux environment for testing eBPF (Apple Silicon Mac)

`lima.yaml` at the repo root provisions Ubuntu 24.04 ARM64 with Go 1.22 +
clang + libbpf-dev + bpftool already installed, with the Mac's `~` mounted
read-write inside the VM. Edit on the Mac, run inside the VM.

```bash
brew install lima
limactl start --name=xray-dev ./lima.yaml

# enter the VM
limactl shell xray-dev
cd /Users/<you>/src/github.com/trentas/xray
make test
sudo ./bin/xray --pid 1 --no-ebpf

# clean up when done
limactl stop xray-dev && limactl delete xray-dev
```

On Intel Macs, swap `vmType: vz` for `vmType: qemu` in `lima.yaml`.

See [CLAUDE.md](CLAUDE.md) for the implementation guide and collector contracts.
