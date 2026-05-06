.PHONY: all build build-ebpf run gen clean dev test test-all vet lint

.DEFAULT_GOAL := all

BINARY := ptop
PKG    := ./cmd/ptop

# ─── all ─────────────────────────────────────────────────────────────────────

# Full developer/CI verification. Compiles the eBPF programs, vets and tests
# both lanes (default + -tags=ebpf), then produces the eBPF-embedded binary.
# Requires Linux + clang + libbpf-dev to compile the .bpf.c programs.
all: gen vet test-all build-ebpf

# ─── eBPF compilation ────────────────────────────────────────────────────────

# Detect arch to set __TARGET_ARCH_<...> in clang and the GNU multiarch
# triple, which points to the `asm/` headers installed by libc6-dev on
# Debian/Ubuntu (e.g. /usr/include/x86_64-linux-gnu/asm/types.h).
BPF_ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')

ifeq ($(BPF_ARCH),x86)
  GNU_TRIPLE := x86_64-linux-gnu
else ifeq ($(BPF_ARCH),arm64)
  GNU_TRIPLE := aarch64-linux-gnu
else
  # Fallback: try gcc -print-multiarch (covers Debian/Ubuntu on any arch)
  GNU_TRIPLE := $(shell gcc -print-multiarch 2>/dev/null)
endif

# List of eBPF programs to compile. Add new .bpf.c files here.
BPF_SRCS := \
	internal/bpf/programs/syscalls.bpf.c \
	internal/bpf/programs/cpu.bpf.c \
	internal/bpf/programs/io.bpf.c \
	internal/bpf/programs/network.bpf.c \
	internal/bpf/programs/threads.bpf.c \
	internal/bpf/programs/memory.bpf.c \
	internal/bpf/programs/futex.bpf.c

BPF_OBJS := $(BPF_SRCS:.c=.o)

CLANG  ?= clang

# Default rule: .bpf.c → .bpf.o via clang -target bpf.
# `-target bpf`: emit BPF bytecode instead of native
# `-O2 -g`: optimization + dwarf info (BPF verifier uses the DWARF)
# `-D__TARGET_ARCH_*`: define used by bpf_tracing.h for pt_regs offsets
# `-I/usr/include/$GNU_TRIPLE`: required to find `asm/types.h` etc.
%.bpf.o: %.bpf.c
	$(CLANG) -O2 -g -target bpf \
		-D__TARGET_ARCH_$(BPF_ARCH) \
		-I/usr/include \
		$(if $(GNU_TRIPLE),-I/usr/include/$(GNU_TRIPLE),) \
		-c $< -o $@

# `make gen` produces all .o files from programs/. Requires libbpf-dev.
gen: $(BPF_OBJS)

# ─── builds ──────────────────────────────────────────────────────────────────

# Build without eBPF — TUI + /proc collectors. Useful on Linux without root,
# or for quick iteration when you don't need kernel-level tracing.
build:
	go build -o bin/$(BINARY) $(PKG)

# Full build with embedded eBPF. Prerequisite: `make gen` (auto via dep).
build-ebpf: gen
	go build -tags=ebpf -o bin/$(BINARY) $(PKG)

# eBPF mode requires root or CAP_BPF + CAP_PERFMON
run: build-ebpf
	sudo ./bin/$(BINARY) --pid $(PID)

# /proc-only mode — no root, no eBPF
dev: build
	./bin/$(BINARY) --pid $(PID) --no-ebpf

# ─── test / lint ─────────────────────────────────────────────────────────────

test:
	go test -race ./...

# Runs tests in both lanes. The eBPF lane requires .bpf.o (run `make gen`).
test-all: test
	$(MAKE) gen && go test -race -tags=ebpf ./...

vet:
	go vet ./...
	@if ls $(BPF_OBJS) >/dev/null 2>&1; then \
		go vet -tags=ebpf ./...; \
	else \
		echo "(go vet -tags=ebpf skipped: run 'make gen' first)"; \
	fi

clean:
	rm -rf bin/
	find . -name "*.bpf.o" -delete

lint:
	golangci-lint run ./...
