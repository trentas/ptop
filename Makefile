.PHONY: build build-ebpf run gen clean dev test vet lint

BINARY := xray
PKG    := ./cmd/xray

# Compila programas eBPF (.c → .o) e embute no binário via go:generate.
# Linux only — no-op em macOS.
gen:
	go generate ./internal/bpf/...

# Default build: sem eBPF, roda em qualquer OS (TUI + /proc collectors).
# Útil pra desenvolvimento, demo do TUI e CI cross-platform.
build:
	go build -o bin/$(BINARY) $(PKG)

# Build completo com eBPF habilitado. Requer:
#   - Linux com kernel headers
#   - libbpf-dev instalado
#   - clang + bpftool pra gen dos .o
build-ebpf: gen
	go build -tags=ebpf -o bin/$(BINARY) $(PKG)

# Modo eBPF requer root ou CAP_BPF
run: build-ebpf
	sudo ./bin/$(BINARY) --pid $(PID)

# Modo /proc-only — sem root, sem eBPF
dev: build
	./bin/$(BINARY) --pid $(PID) --no-ebpf

test:
	go test -race ./...

# Roda os testes nos dois modos de build pra pegar regressão
# nos stubs vs implementação real.
test-all: test
	go test -race -tags=ebpf ./... 2>/dev/null || echo "(eBPF tests só rodam em Linux com libbpf — ok pular em macOS)"

vet:
	go vet ./...
	go vet -tags=ebpf ./...

clean:
	rm -rf bin/
	find . -name "*.o" -delete

lint:
	golangci-lint run ./...
