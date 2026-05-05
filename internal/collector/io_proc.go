package collector

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// IOThroughputCollector lê /proc/<pid>/io a cada 500ms e calcula:
//
//   - ReadBytesPerS / WriteBytesPerS via delta de read_bytes / write_bytes
//     (camada de storage — exclui hits de cache, mais coerente com `iotop`)
//   - ReadOps / WriteOps cumulativos via syscr / syscw (camada de syscall)
//
// Observação: read_bytes/write_bytes só registra I/O que efetivamente toca o
// dispositivo. Pra captar throughput "lógico" incluindo cache, usar
// rchar/wchar — mas a camada lógica infla quando o processo relê o mesmo
// arquivo várias vezes (cache hit), o que não é o que o usuário quer ver
// no gráfico de throughput. read_bytes/write_bytes está mais alinhado com
// o que o `iotop` reporta e com o que vai virar real-deal sob eBPF (#11).
type IOThroughputCollector struct {
	pid  int
	ch   chan interface{}
	stop chan struct{}
	mu   sync.Mutex

	lastReadBytes  uint64
	lastWriteBytes uint64
	lastAt         time.Time
}

func NewIOThroughputCollector() *IOThroughputCollector {
	return &IOThroughputCollector{
		ch:   make(chan interface{}, 16),
		stop: make(chan struct{}),
	}
}

func (c *IOThroughputCollector) Start(pid int) error {
	c.pid = pid
	if _, err := os.Stat(fmt.Sprintf("/proc/%d/io", pid)); err != nil {
		// /proc/<pid>/io só está disponível pra processos do mesmo UID
		// (ou root). Se não dá pra ler, falha imediato — modelo cai em mock.
		return fmt.Errorf("não foi possível abrir /proc/%d/io: %w", pid, err)
	}
	go c.loop()
	return nil
}

func (c *IOThroughputCollector) Stop()                          { close(c.stop) }
func (c *IOThroughputCollector) Subscribe() <-chan interface{}  { return c.ch }

func (c *IOThroughputCollector) loop() {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			if s, err := c.sample(); err == nil {
				select {
				case c.ch <- s:
				default:
				}
			}
		}
	}
}

func (c *IOThroughputCollector) sample() (IOThroughputSample, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/io", c.pid))
	if err != nil {
		return IOThroughputSample{}, err
	}
	io, err := parseProcIO(data)
	if err != nil {
		return IOThroughputSample{}, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var rps, wps float64
	if !c.lastAt.IsZero() {
		elapsed := now.Sub(c.lastAt).Seconds()
		if elapsed > 0 {
			if io.readBytes >= c.lastReadBytes {
				rps = float64(io.readBytes-c.lastReadBytes) / elapsed
			}
			if io.writeBytes >= c.lastWriteBytes {
				wps = float64(io.writeBytes-c.lastWriteBytes) / elapsed
			}
		}
	}
	c.lastReadBytes = io.readBytes
	c.lastWriteBytes = io.writeBytes
	c.lastAt = now

	return IOThroughputSample{
		ReadBytesPerS:  rps,
		WriteBytesPerS: wps,
		ReadOps:        io.syscr,
		WriteOps:       io.syscw,
		Timestamp:      now,
	}, nil
}

// procIOFields contém os campos de /proc/<pid>/io que nos interessam.
// Formato canônico (1 par "key: value" por linha):
//
//	rchar: 1234
//	wchar: 5678
//	syscr: 100
//	syscw: 50
//	read_bytes: 4096
//	write_bytes: 8192
//	cancelled_write_bytes: 0
type procIOFields struct {
	rchar      uint64
	wchar      uint64
	syscr      uint64
	syscw      uint64
	readBytes  uint64
	writeBytes uint64
}

func parseProcIO(data []byte) (procIOFields, error) {
	var io procIOFields
	parsed := 0
	for _, line := range strings.Split(string(data), "\n") {
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		key := strings.TrimSpace(line[:colon])
		value := strings.TrimSpace(line[colon+1:])
		n, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			continue
		}
		switch key {
		case "rchar":
			io.rchar = n
		case "wchar":
			io.wchar = n
		case "syscr":
			io.syscr = n
		case "syscw":
			io.syscw = n
		case "read_bytes":
			io.readBytes = n
		case "write_bytes":
			io.writeBytes = n
		}
		parsed++
	}
	if parsed == 0 {
		return io, fmt.Errorf("malformed /proc io: nenhum par chave:valor")
	}
	return io, nil
}
