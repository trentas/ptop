.PHONY: build build-ebpf run gen clean dev test test-all vet lint

BINARY := xray
PKG    := ./cmd/xray

# ─── eBPF compilation ────────────────────────────────────────────────────────

# Detecta arch pra setar __TARGET_ARCH_<...> no clang e o GNU multiarch
# triple, que aponta pros headers `asm/` instalados pelo libc6-dev em
# Debian/Ubuntu (ex: /usr/include/x86_64-linux-gnu/asm/types.h).
BPF_ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')

ifeq ($(BPF_ARCH),x86)
  GNU_TRIPLE := x86_64-linux-gnu
else ifeq ($(BPF_ARCH),arm64)
  GNU_TRIPLE := aarch64-linux-gnu
else
  # Fallback: tenta gcc -print-multiarch (cobre Debian/Ubuntu em qualquer arch)
  GNU_TRIPLE := $(shell gcc -print-multiarch 2>/dev/null)
endif

# Lista de programas eBPF a compilar. Adicionar novos .bpf.c aqui.
BPF_SRCS := \
	internal/bpf/programs/syscalls.bpf.c \
	internal/bpf/programs/cpu.bpf.c

BPF_OBJS := $(BPF_SRCS:.c=.o)

CLANG  ?= clang

# Regra padrão: .bpf.c → .bpf.o via clang -target bpf.
# `-target bpf`: emite bytecode BPF em vez de nativo
# `-O2 -g`: otimização + dwarf info (verificador BPF aproveita os DWARF)
# `-D__TARGET_ARCH_*`: define usado por bpf_tracing.h pra pt_regs offsets
# `-I/usr/include/$GNU_TRIPLE`: necessário pra encontrar `asm/types.h` etc.
%.bpf.o: %.bpf.c
	$(CLANG) -O2 -g -target bpf \
		-D__TARGET_ARCH_$(BPF_ARCH) \
		-I/usr/include \
		$(if $(GNU_TRIPLE),-I/usr/include/$(GNU_TRIPLE),) \
		-c $< -o $@

# `make gen` produz todos os .o de programs/. Roda só em Linux com libbpf-dev.
gen: $(BPF_OBJS)

# ─── builds ──────────────────────────────────────────────────────────────────

# Default build: SEM eBPF, qualquer OS (TUI + /proc collectors).
build:
	go build -o bin/$(BINARY) $(PKG)

# Build completo com eBPF embarcado. Pré-requisito: `make gen` (auto via dep).
build-ebpf: gen
	go build -tags=ebpf -o bin/$(BINARY) $(PKG)

# Modo eBPF requer root ou CAP_BPF
run: build-ebpf
	sudo ./bin/$(BINARY) --pid $(PID)

# Modo /proc-only — sem root, sem eBPF
dev: build
	./bin/$(BINARY) --pid $(PID) --no-ebpf

# ─── test / lint ─────────────────────────────────────────────────────────────

test:
	go test -race ./...

# Roda testes nos dois modos. Ebpf lane só faz sentido em Linux (dependência
# do .bpf.o); pula com aviso em outros OSes.
test-all: test
	@if [ "$$(uname)" = "Linux" ]; then \
		$(MAKE) gen && go test -race -tags=ebpf ./...; \
	else \
		echo "(eBPF tests só rodam em Linux com libbpf-dev — pulando)"; \
	fi

vet:
	go vet ./...
	@if ls $(BPF_OBJS) >/dev/null 2>&1; then \
		go vet -tags=ebpf ./...; \
	else \
		echo "(go vet -tags=ebpf pulado: rode 'make gen' primeiro)"; \
	fi

clean:
	rm -rf bin/
	find . -name "*.bpf.o" -delete

lint:
	golangci-lint run ./...
