# xray

TUI para inspeção profunda de processos Linux via eBPF.

```
⬡ xray  api-server  PID 18423  Go 1.22  RUNNING  15 fds
────────────────────────────────────────────────────────────────
 F1 Overview │ F2 Syscalls │ F3 Network │ F4 Threads │ F5 I/O │ F6 FD │ F7 Timeline
```

## Requisitos

- Linux kernel 5.8+ (BTF + ring buffer)
- `clang` e `bpftool` para compilar os programas eBPF
- Go 1.22+
- root ou `CAP_BPF` para modo completo

## Instalação

```bash
git clone git@github.com:trentas/xray.git
cd xray
make build
```

## Uso

```bash
# modo completo (requer root)
sudo ./bin/xray --pid 1234

# modo desenvolvimento (sem eBPF, lê /proc)
./bin/xray --pid 1234 --no-ebpf

# com taxa de atualização customizada
sudo ./bin/xray --pid 1234 --fps 10
```

## Navegação

| Tecla | Ação |
|-------|------|
| F1–F7 | Trocar aba |
| `p`   | Pausar/retomar |
| `q`   | Sair |
| `/`   | Filtrar (FD view) |
| `s`   | Snapshot |
| `e`   | Exportar JSON |

## Arquitetura

Ver [CLAUDE.md](CLAUDE.md) para spec completa de implementação.

## Referência visual

`assets/mockup.jsx` — protótipo React interativo com dados simulados.
Abre no Claude.ai ou em qualquer sandbox React.
