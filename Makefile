.PHONY: build run gen clean dev

# Compila programas eBPF (.c → .o) e embute no binário via go:generate
gen:
	go generate ./internal/bpf/...

# Build completo com eBPF
build: gen
	go build -o bin/bpf-inspector ./cmd/inspector

# Build sem eBPF (para desenvolvimento/teste sem root)
build-dev:
	go build -tags noebpf -o bin/bpf-inspector ./cmd/inspector

# Requer root para eBPF
run: build
	sudo ./bin/bpf-inspector --pid $(PID)

# Modo desenvolvimento: sem eBPF, dados de /proc
dev: build-dev
	./bin/bpf-inspector --pid $(PID) --no-ebpf

clean:
	rm -rf bin/
	find . -name "*.o" -delete

lint:
	golangci-lint run ./...
