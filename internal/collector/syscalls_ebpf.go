//go:build linux && ebpf

package collector

import (
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/trentas/xray/internal/bpf"
)

// SyscallsEBPFCollector consome o map syscall_count do programa eBPF de
// syscalls (internal/bpf/syscalls.go) e publica um snapshot map[name]Stat
// a cada 500ms para o Model.
//
// Roda só em Linux com -tags=ebpf. Em outros builds, o Stub não-Linux retorna
// nil em New e Start sempre falha.
type SyscallsEBPFCollector struct {
	tracer *bpf.SyscallTracer
	ch     chan interface{}
	stop   chan struct{}

	mu      sync.Mutex
	isARM64 bool
}

func NewSyscallsEBPFCollector() *SyscallsEBPFCollector {
	return &SyscallsEBPFCollector{
		ch:      make(chan interface{}, 16),
		stop:    make(chan struct{}),
		isARM64: runtime.GOARCH == "arm64",
	}
}

func (c *SyscallsEBPFCollector) Start(pid int) error {
	tracer, err := bpf.OpenSyscallTracer(pid)
	if err != nil {
		return fmt.Errorf("syscalls eBPF: %w", err)
	}
	c.tracer = tracer
	go c.loop()
	return nil
}

func (c *SyscallsEBPFCollector) Stop() {
	close(c.stop)
	if c.tracer != nil {
		_ = c.tracer.Close()
		c.tracer = nil
	}
}

func (c *SyscallsEBPFCollector) Subscribe() <-chan interface{} {
	return c.ch
}

func (c *SyscallsEBPFCollector) loop() {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			if snap, err := c.snapshot(); err == nil {
				select {
				case c.ch <- snap:
				default:
				}
			}
		}
	}
}

// snapshot lê o map syscall_count e devolve {name → contagem}.
// Latência fica disponível mas não é exportada por enquanto — o Model só
// consome contagens hoje. Quando F2 ganhar coluna LAT/MED, voltamos aqui.
func (c *SyscallsEBPFCollector) snapshot() (map[string]uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tracer == nil {
		return nil, fmt.Errorf("tracer não aberto")
	}
	stats, err := c.tracer.Stats()
	if err != nil {
		return nil, err
	}
	out := make(map[string]uint64, len(stats))
	for id, st := range stats {
		out[syscallName(id, c.isARM64)] = st.Count
	}
	return out, nil
}
