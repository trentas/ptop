.PHONY: build run gen clean dev test vet lint

BINARY := xray
PKG    := ./cmd/xray

# Compila programas eBPF (.c → .o) e embute no binário via go:generate
gen:
	go generate ./internal/bpf/...

# Build completo com eBPF
build: gen
	go build -o bin/$(BINARY) $(PKG)

# Build sem eBPF (para desenvolvimento/teste sem root)
build-dev:
	go build -tags noebpf -o bin/$(BINARY) $(PKG)

# Requer root para eBPF
run: build
	sudo ./bin/$(BINARY) --pid $(PID)

# Modo desenvolvimento: sem eBPF, dados de /proc
dev: build-dev
	./bin/$(BINARY) --pid $(PID) --no-ebpf

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf bin/
	find . -name "*.o" -delete

lint:
	golangci-lint run ./...
