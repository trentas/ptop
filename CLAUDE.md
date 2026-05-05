# bpf-inspector

TUI interativa para inspeção profunda de processos Linux via eBPF.
Permite diagnóstico ao vivo de CPU, syscalls, rede, I/O, memória, threads e file descriptors
de qualquer processo em execução — sem reiniciar, sem instrumentar, sem alterar uma linha de código.

---

## Stack

| Camada | Tecnologia | Motivo |
|--------|-----------|--------|
| TUI    | [Bubbletea](https://github.com/charmbracelet/bubbletea) + [Lipgloss](https://github.com/charmbracelet/lipgloss) | Ecossistema maduro, composable, suporte a mouse |
| eBPF   | [libbpfgo](https://github.com/aquasecurity/libbpfgo) | Binding oficial Cilium, melhor suporte a CO-RE |
| Build  | Go 1.22+ | Binário único, cross-compile fácil |
| eBPF C | clang + bpftool | Compilar .c → .o → embed no binário via go:generate |

> Não use CGO além do que libbpfgo já requer. Não use frameworks de CLI (cobra, urfave) — o entrypoint é simples.

---

## Referência visual

`assets/mockup.jsx` contém o protótipo React completo com todas as abas implementadas e dados simulados.
**Cada view Go deve reproduzir fielmente o layout do mockup correspondente.**
Use-o como spec visual autoritativa — se houver dúvida sobre layout, o mockup prevalece.

Paleta de cores (usar via Lipgloss):
```
bg:      #0e1014    bgPanel: #13161c    border:  #2a2d35
dim:     #3a3d45    muted:   #5a5f72    text:    #c8ccd8
bright:  #e8ecf5    green:   #4ade80    cyan:    #22d3ee
amber:   #fbbf24    red:     #f87171    blue:    #60a5fa
purple:  #a78bfa    pink:    #f472b6    orange:  #fb923c
teal:    #2dd4bf
```

---

## Estrutura do projeto

```
bpf-inspector/
├── CLAUDE.md
├── go.mod
├── go.sum
├── Makefile
├── cmd/
│   └── inspector/
│       └── main.go          # entrypoint: parse args, inicializa collectors, inicia TUI
├── internal/
│   ├── bpf/
│   │   ├── programs/        # fontes .c dos programas eBPF
│   │   │   ├── syscalls.bpf.c
│   │   │   ├── network.bpf.c
│   │   │   ├── io.bpf.c
│   │   │   └── fds.bpf.c
│   │   ├── loader.go        # carrega e gerencia os programas eBPF
│   │   └── maps.go          # definições dos BPF maps compartilhados
│   ├── collector/
│   │   ├── types.go         # structs de dados compartilhados entre collectors e TUI
│   │   ├── cpu.go           # perf_event sampling → histórico de CPU
│   │   ├── syscalls.go      # tracepoint syscalls:sys_enter_* → contagens + latência
│   │   ├── network.go       # sock tracepoints → conexões ativas, latência por peer
│   │   ├── memory.go        # mmap/brk/page faults via tracepoints
│   │   ├── threads.go       # sched tracepoints → estado de threads + off-cpu
│   │   ├── io.go            # block I/O tracepoints → throughput, latência, top files
│   │   └── fds.go           # openat/close/dup2 uprobes → tabela de FDs ao vivo
│   └── tui/
│       ├── model.go         # Bubbletea root model: estado global, roteamento de msgs
│       ├── keys.go          # keybindings (F1-F7, q, p, /, s, e)
│       ├── styles.go        # todas as definições Lipgloss (cores, bordas, badges)
│       ├── header.go        # barra superior: nome, PID, runtime, badge fd count, uptime
│       ├── tabbar.go        # barra de abas F1-F7
│       ├── statusbar.go     # rodapé com keybindings e info de overhead
│       ├── sparkline.go     # componente reutilizável de sparkline SVG-style em braille
│       └── views/
│           ├── overview.go  # F1: CPU + syscalls + threads + I/O mini + net + mem + timeline
│           ├── syscalls.go  # F2: barras de frequência + percentual + event stream
│           ├── network.go   # F3: conexões ativas + latency trend + net events
│           ├── threads.go   # F4: thread state + lock graph + lock events
│           ├── io.go        # F5: throughput dual + top files + latency histogram + stats
│           ├── fd.go        # F6: fd table + breakdown + sparkline + alertas + fd events
│           └── timeline.go  # F7: full event stream com badge por categoria
└── assets/
    └── mockup.jsx           # protótipo React — referência visual autoritativa
```

---

## Tipos de dados centrais (`internal/collector/types.go`)

Todos os collectors publicam para canais tipados consumidos pelo model Bubbletea.

```go
// Msg enviada pelo collector de CPU a cada tick
type CpuSample struct {
    UsagePct float64
    Timestamp time.Time
}

// Msg de syscall
type SyscallEvent struct {
    Name      string
    Count     uint64
    LatencyNs uint64
}

// Conexão de rede ativa
type NetConn struct {
    FD       int
    Type     string // "TCP" | "UDP" | "UNIX"
    Remote   string
    State    string // "ESTABLISHED" | "WAIT" | "RECV" | ...
    LatencyMs float64
    TxBytes  uint64
    RxBytes  uint64
}

// Evento de I/O
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
    Desc     string // path ou endereço remoto
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
    Waiting string // nome do lock/syscall bloqueante, se houver
}

// Evento genérico do timeline
type TimelineEvent struct {
    Timestamp time.Time
    Category  string // "syscall"|"net"|"mem"|"cpu"|"lock"|"io"|"fd"
    Message   string
}
```

---

## Collectors — contrato de implementação

Cada collector implementa esta interface:

```go
type Collector interface {
    Start(ctx context.Context, pid int) error
    Stop()
    Subscribe() <-chan interface{} // envia msgs tipadas acima
}
```

O model Bubbletea faz `select` em todos os canais via `tea.Cmd` wrapping `waitForMsg`.

### Prioridade de implementação

1. `syscalls.go` — mais impactante, usa tracepoints estáveis
2. `cpu.go` — perf_event, independente de versão de kernel
3. `fds.go` — leitura de `/proc/{pid}/fd` + eventos eBPF para openat/close
4. `io.go` — block tracepoints
5. `network.go` — sock tracepoints
6. `threads.go` — sched tracepoints
7. `memory.go` — mmap/fault tracepoints

> Para o MVP, `fds.go` pode ler `/proc/{pid}/fd` polling a cada 500ms sem eBPF.
> Os demais devem usar eBPF desde o início.

---

## TUI — regras de implementação

### Bubbletea model

```go
type Model struct {
    // dados coletados
    CPUHistory    []float64       // últimos 60 samples
    SyscallCounts map[string]uint64
    NetConns      []collector.NetConn
    MemStats      collector.MemStats
    Threads       []collector.ThreadInfo
    IOStats       collector.IOStats
    FDs           []collector.FDEntry
    Timeline      []collector.TimelineEvent

    // estado da UI
    ActiveTab     int
    FDFilter      string          // "all"|"file"|"socket"|...
    Paused        bool
    Width, Height int
}
```

### Mensagens Bubbletea

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

### Sparkline em braille

Use blocos braille Unicode para sparklines — é o padrão TUI moderno.
Caracteres: `⣀⣄⣆⣇⡇⡏⡟⡿` (escala de 8 níveis por coluna).
Implemente em `tui/sparkline.go` como função pura `Sparkline(data []float64, width int, color lipgloss.Color) string`.

### Layout

Use `lipgloss.JoinHorizontal` e `lipgloss.JoinVertical` para compor painéis.
Cada view recebe `width, height int` e retorna `string` — sem estado interno.
O model root distribui dimensões via `tea.WindowSizeMsg`.

---

## Makefile

```makefile
.PHONY: build run gen clean

# compila os programas eBPF e embute no binário
gen:
	go generate ./internal/bpf/...

build: gen
	go build -o bin/bpf-inspector ./cmd/inspector

# requer root para eBPF
run: build
	sudo ./bin/bpf-inspector --pid $(PID)

clean:
	rm -rf bin/
```

---

## Flags de linha de comando

```
bpf-inspector --pid <PID>            # inspecionar processo específico
bpf-inspector --pid <PID> --fps 10   # taxa de atualização (default: 5)
bpf-inspector --pid <PID> --export   # salvar snapshot JSON ao sair (tecla 'e')
bpf-inspector --pid <PID> --no-ebpf  # modo degradado: só /proc, sem eBPF (para testes)
```

---

## Ordem de implementação sugerida para Claude Code

1. `go.mod` + dependências (bubbletea, lipgloss, libbpfgo)
2. `internal/collector/types.go` — todos os tipos
3. `internal/tui/styles.go` — paleta completa em Lipgloss
4. `internal/tui/sparkline.go` — componente braille reutilizável
5. `internal/tui/header.go`, `tabbar.go`, `statusbar.go`
6. `internal/tui/model.go` — com dados mockados (--no-ebpf mode)
7. Cada view em `internal/tui/views/` — começar por `overview.go`
8. `internal/collector/fds.go` — polling /proc sem eBPF
9. `internal/collector/syscalls.go` — primeiro collector eBPF real
10. Demais collectors

> Itens 1-7 constroem a TUI completa com dados simulados, verificável sem root.
> Itens 8-10 conectam à realidade um collector por vez.

---

## Notas de segurança

- eBPF requer `CAP_BPF` ou root. O binário deve checar e imprimir erro claro se não tiver permissão.
- No modo `--no-ebpf`, todos os collectors caem para leitura de `/proc` — útil para desenvolvimento.
- Nunca fazer `panic` em produção — collectors devem logar erros e continuar.
