# xray

TUI interativa para inspeção profunda de processos Linux via eBPF.
Diagnóstico ao vivo de CPU, syscalls, rede, I/O, memória, threads e file
descriptors — sem reiniciar, sem instrumentar, sem alterar uma linha
de código do alvo.

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

> Frame acima é dump real de `go test` em modo `--no-ebpf`. Roda em qualquer terminal moderno.
> A versão React do mockup está em [`assets/mockup.jsx`](assets/mockup.jsx) — referência visual autoritativa.

---

## Quickstart

### Pré-requisitos

- **macOS / dev (sem eBPF):** Go 1.22+
- **Linux (modo completo):** Go 1.22+, kernel 5.8+ (BTF + ring buffer), `clang`, `bpftool`, `libbpf-dev`, root ou `CAP_BPF`

### Build

```bash
git clone git@github.com:trentas/xray.git
cd xray

# default — sem eBPF, qualquer OS (TUI + /proc collectors)
make build

# com eBPF embarcado — Linux only, requer libbpf
make build-ebpf
```

### Run

```bash
# modo /proc-only (Linux + macOS dev)
./bin/xray --pid 1234 --no-ebpf

# modo completo (Linux com sudo)
sudo ./bin/xray --pid 1234

# taxa de atualização customizada (default: 5fps de render, sim a cada 700ms)
sudo ./bin/xray --pid 1234 --fps 10

# salvar snapshot JSON ao sair
sudo ./bin/xray --pid 1234 --export
```

### Navegação

| Tecla | Ação |
|-------|------|
| `F1`–`F7` | Trocar aba |
| `Tab` / `Shift+Tab` | Próxima / anterior aba |
| `1`–`7` | Atalho da aba (alternativa ao F1-F7) |
| `p`, `Space` | Pausar / retomar simulação |
| `/` | Filtrar (cicla tipos na F6) |
| `q`, `Ctrl+C` | Sair |
| `s` | Snapshot JSON (planejado #15) |
| `e` | Toggle export contínuo (planejado #15) |

---

## Status dos collectors

Cada aba pode ser alimentada por 3 fontes diferentes, dependendo do modo. ✅ = real, ⚠️ = planejado, ❌ = sem fonte naquele modo.

| Aba | macOS dev | `--no-ebpf` (Linux) | eBPF (`-tags=ebpf` + sudo) |
|---|---|---|---|
| **F1 Overview**     | mock | ✅ CPU + Mem + Threads + I/O + FDs | ⚠️ refinado por #9-#14 |
| **F2 Syscalls**     | mock | ❌ não há fonte `/proc` | ⚠️ #9 (raw_syscalls tracepoint) |
| **F3 Network**      | mock | ✅ conexões via `/proc/net/{tcp,udp,unix}` | ⚠️ #12 (latência por peer) |
| **F4 Threads**      | mock | ✅ state + CPU% + waiting (wchan) | ⚠️ #13 (off-CPU + lock graph) |
| **F5 I/O**          | mock | ✅ throughput (`/proc/<pid>/io`) + iowait (campo 42) | ⚠️ #11 (top files + latência por op) |
| **F6 FDs**          | mock | ✅ completo: sockets resolvidos, bytes, active, eventos | ⚠️ #11 (active correto p/ sockets) |
| **F7 Timeline**     | mock | parcial — só categoria `fd` tem fonte real | ⚠️ todas via #9-#14 |

### Fontes implementadas

- `internal/collector/cpu_proc.go` — `/proc/<pid>/stat` campos 14-15 (utime+stime)
- `internal/collector/threads_proc.go` — `/proc/<pid>/task/*/stat` + `wchan`
- `internal/collector/mem_proc.go` — `/proc/<pid>/statm` + page faults
- `internal/collector/iowait_proc.go` — `/proc/<pid>/stat` campo 42 (delayacct_blkio_ticks)
- `internal/collector/io_proc.go` — `/proc/<pid>/io` (read_bytes/write_bytes/syscr/syscw)
- `internal/collector/fds.go` + `sockets.go` — `/proc/<pid>/fd`, `/proc/<pid>/fdinfo`, `/proc/net/{tcp,tcp6,udp,udp6,unix}`

### Limitações conhecidas (modo `--no-ebpf`)

- **CPU%**: clkTck hardcoded em 100Hz (default x86/x86_64). ARM com `CONFIG_HZ=250` reporta 2.5× menor.
- **F2 Syscalls** vazio: não há contador per-syscall em `/proc`.
- **F7 Timeline** parcial: só eventos de FD (open/close/dup) em modo `/proc`. Demais categorias precisam tracepoints eBPF.
- **CAP_BPF / SIP**: ver [issue #19](https://github.com/trentas/xray/issues/19).

---

## Arquitetura

```
xray/
├── cmd/xray/                  entrypoint: parse flags, inicia model
├── internal/
│   ├── bpf/                   programas eBPF + loader (tag `ebpf`)
│   ├── collector/             coletores /proc + tipos compartilhados
│   │   ├── types.go           CpuSample, IOWaitSample, FDEntry, ...
│   │   ├── cpu_proc.go        /proc/<pid>/stat utime+stime
│   │   ├── threads_proc.go    /proc/<pid>/task/*/stat + wchan
│   │   ├── mem_proc.go        /proc/<pid>/statm + faults
│   │   ├── iowait_proc.go     campo 42 (block I/O wait)
│   │   ├── io_proc.go         /proc/<pid>/io (throughput + ops)
│   │   ├── fds.go             /proc/<pid>/fd + fdinfo + open/close events
│   │   └── sockets.go         resolução de inodes via /proc/net/*
│   └── tui/                   Bubbletea + Lipgloss
│       ├── model.go           estado global, roteamento de msgs
│       ├── keys.go            keybindings F1-F7, q, p, /, s, e
│       ├── styles.go          paleta + estilos Lipgloss
│       ├── sparkline.go       sparklines em braille
│       ├── panel.go           caixa titulada (helper de layout)
│       ├── header.go          barra superior (badges + uptime + clock)
│       ├── tabbar.go          F1-F7
│       ├── statusbar.go       rodapé com keybindings
│       ├── panels.go          renderers reutilizáveis
│       └── view_*.go          7 views (overview + syscalls + network + ...)
└── assets/
    ├── mockup.jsx                   spec visual autoritativa em React
    └── screenshot-overview.txt      dump do F1 em --no-ebpf
```

Ver [`CLAUDE.md`](CLAUDE.md) para spec completa de implementação e referência de tipos.

---

## Roadmap

**Fechado** (PRs #23-#29):
- ✅ TUI completa em todas as 7 abas
- ✅ Coletores `/proc` para CPU, threads, memória, I/O wait, throughput, FDs
- ✅ Resolução de socket inodes (TCP/UDP/UNIX)
- ✅ Eventos open/close/dup de FDs
- ✅ CI (vet + race + build, default + tags=ebpf)
- ✅ Build tags isolando código eBPF

**Próximo bloco — qualidade de vida:**
- [#15](https://github.com/trentas/xray/issues/15) snapshot/export JSON
- [#16](https://github.com/trentas/xray/issues/16) input filter `/` + help overlay `?`
- [#19](https://github.com/trentas/xray/issues/19) UX de capabilities (CAP_BPF/PERFMON)
- [#20](https://github.com/trentas/xray/issues/20) release tooling

**Próximo bloco — eBPF:**
- [#9](https://github.com/trentas/xray/issues/9) syscalls.bpf.c + loader (raw_syscalls tracepoint)
- [#10](https://github.com/trentas/xray/issues/10) CPU sampling via perf_event
- [#11](https://github.com/trentas/xray/issues/11) block I/O tracepoints (top files + latência)
- [#12](https://github.com/trentas/xray/issues/12) network sock tracepoints
- [#13](https://github.com/trentas/xray/issues/13) sched tracepoints + off-CPU profiling
- [#14](https://github.com/trentas/xray/issues/14) memory tracepoints

**Future ports** (não-bloqueador, OS específico):
- [#21](https://github.com/trentas/xray/issues/21) Windows 11 via ETW (eBPF for Windows é só rede)
- [#22](https://github.com/trentas/xray/issues/22) macOS via libproc + Mach (DTrace bloqueado por SIP em OSS)

---

## Desenvolvimento

```bash
make test            # go test -race ./...
make vet             # vet em ambos modos (default + tags=ebpf)
make clean           # rm -rf bin/
make lint            # golangci-lint (precisa instalar)
```

Ver [CLAUDE.md](CLAUDE.md) para guia de implementação e contratos dos collectors.
