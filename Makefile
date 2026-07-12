.PHONY: all build build-ebpf run gen proto proto-lint clean dev test test-all vet lint install install-bare install-ebpf uninstall ebpf-selftest

.DEFAULT_GOAL := all

BINARY := ptop
PKG    := ./cmd/ptop

# Go toolchain. Override when `go` isn't on the invoking user's PATH — notably
# under `sudo`, which resets PATH to a secure_path that omits /usr/local/go/bin:
#   sudo make install GO=$(which go)
# (or just `sudo env "PATH=$PATH" make install` to carry your PATH through).
GO     ?= go

# Install location — override via `make install PREFIX=~/.local` for a
# no-sudo user install, or `make install PREFIX=/opt/local` etc. DESTDIR
# is the standard packager-staging variable (kept empty in regular use).
PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
DESTDIR ?=

# `make install` picks the most capable build for the host OS:
#   - Linux: eBPF-embedded (full F2/F3/F5/F7 + rich CPU/threads/mem).
#   - other: the bare libproc-based build (macOS Tier 1; see #22).
# Override with `make install-ebpf` / `make install-bare` for explicit control.
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
  INSTALL_DEFAULT := install-ebpf
else
  INSTALL_DEFAULT := install-bare
endif

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
	internal/bpf/programs/heap.bpf.c \
	internal/bpf/programs/futex.bpf.c \
	internal/bpf/programs/signal.bpf.c \
	internal/bpf/programs/tls.bpf.c \
	internal/bpf/programs/proc.bpf.c \
	internal/bpf/programs/security.bpf.c

BPF_OBJS := $(BPF_SRCS:.c=.o)

# Every BPF object includes the shared filter header — editing it must
# trigger a rebuild (the %.bpf.o rule below only tracks the .c file).
$(BPF_OBJS): internal/bpf/programs/target.bpf.h

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

# ─── protobuf codegen ─────────────────────────────────────────────────────────

# buf is pinned via `go run @version` rather than added to go.mod — it keeps the
# module lean (only google.golang.org/protobuf, the runtime dep, is required).
# The codegen plugin is a pinned remote plugin (see buf.gen.yaml), so no local
# protoc-gen-go install is needed. The generated pkg/streampb/*.pb.go is
# committed, so this target is NOT part of `all` — only run it after editing
# proto/event.proto.
BUF_VERSION ?= v1.70.0
BUF         := $(GO) run github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)

proto:
	$(BUF) format -w
	$(BUF) lint
	$(BUF) generate

proto-lint:
	$(BUF) lint

# ─── builds ──────────────────────────────────────────────────────────────────

# Go sources (excluding tests + build output) — prerequisites of the binary so
# it's relinked only when something that affects it actually changed.
GO_SRCS := $(shell find . -type f -name '*.go' -not -name '*_test.go' -not -path './bin/*')

# Build without eBPF — TUI + /proc collectors. Useful on Linux without root,
# or for quick iteration when you don't need kernel-level tracing. Removes the
# ebpf lane stamp (see below): both lanes write the same output file, so a
# bare build must invalidate the eBPF file target.
build:
	@rm -f bin/.lane-ebpf
	$(GO) build -o bin/$(BINARY) $(PKG)

# Lane check, done at PARSE time via $(shell): if the last bin/$(BINARY) was
# not built by the ebpf lane (stamp absent), inject FORCE so the relink always
# runs. mtime comparison can't express this — macOS ships GNU Make 3.81 with
# 1-second resolution and a cached stat of the target, so a stamp file as a
# plain prerequisite misses same-second lane switches.
EBPF_LANE_FORCE := $(shell test -f bin/.lane-ebpf || echo FORCE)

FORCE:
.PHONY: FORCE

# eBPF-embedded binary as a REAL file target: rebuilt only when a .go source, a
# compiled .bpf.o, or go.mod/go.sum changes (or the lane switched — see above).
# This is what makes the `make` (as your user) → `sudo make install` flow
# cheap — install reuses the binary you already built instead of recompiling
# under root's cold caches, which otherwise re-downloads the Go toolchain and
# every dependency. The stamp is written only after a successful link, so an
# interrupted build still forces the next one.
bin/$(BINARY): $(GO_SRCS) $(BPF_OBJS) go.mod go.sum $(EBPF_LANE_FORCE)
	$(GO) build -tags=ebpf -o $@ $(PKG)
	@touch bin/.lane-ebpf

# Phony alias for the eBPF binary (keeps `make build-ebpf` / `make run` working).
build-ebpf: bin/$(BINARY)

# eBPF mode requires root or CAP_BPF + CAP_PERFMON
run: build-ebpf
	sudo ./bin/$(BINARY) --pid $(PID)

# /proc-only mode — no root, no eBPF
dev: build
	./bin/$(BINARY) --pid $(PID) --no-ebpf

# ebpf-selftest builds the eBPF self-diagnostic. Run the result as root:
# `sudo ./bin/ebpf-selftest` — it reports whether the eBPF collectors can
# observe the target process (useful inside containers / WSL).
ebpf-selftest: gen
	$(GO) build -tags=ebpf -o bin/ebpf-selftest ./cmd/ebpfselftest
	@echo "built bin/ebpf-selftest — run as root: sudo ./bin/ebpf-selftest"

# ─── test / lint ─────────────────────────────────────────────────────────────

test:
	$(GO) test -race ./...

# Runs tests in both lanes. The eBPF lane requires .bpf.o (run `make gen`).
test-all: test
	$(MAKE) gen && $(GO) test -race -tags=ebpf ./...

vet:
	$(GO) vet ./...
	@if ls $(BPF_OBJS) >/dev/null 2>&1; then \
		$(GO) vet -tags=ebpf ./...; \
	else \
		echo "(go vet -tags=ebpf skipped: run 'make gen' first)"; \
	fi

clean:
	rm -rf bin/
	find . -name "*.bpf.o" -delete

lint:
	golangci-lint run ./...

# ─── install ─────────────────────────────────────────────────────────────────

# `make install` is the user-facing entry point — it picks the right variant
# for the host OS (see INSTALL_DEFAULT above). Default destination is
# /usr/local/bin which needs sudo; override with `make install PREFIX=~/.local`
# for a user-local install. install(1) exists on both macOS and Linux and
# handles both creation of the target dir (-d) and permissions (-m) in one
# shot.
#
# Recommended flow: `make` (as your user, warm caches) then `sudo make install`
# — the latter only copies the already-built binary. Building under sudo works
# (`sudo make install GO=$(which go)`) but recompiles in root's cold cache.
install: $(INSTALL_DEFAULT)

install-bare: build
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 bin/$(BINARY) $(DESTDIR)$(BINDIR)/$(BINARY)
	@echo "installed $(DESTDIR)$(BINDIR)/$(BINARY)"

# Linux-only flavor: eBPF-embedded binary. Requires `make gen`
# (libbpf-dev + clang). On macOS this target will fail at the gen step
# since the kernel headers aren't there — use `install` (the default
# alias dispatches by OS).
install-ebpf: bin/$(BINARY)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 bin/$(BINARY) $(DESTDIR)$(BINDIR)/$(BINARY)
	@echo "installed $(DESTDIR)$(BINDIR)/$(BINARY) (with embedded eBPF)"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BINARY)
	@echo "removed $(DESTDIR)$(BINDIR)/$(BINARY)"
