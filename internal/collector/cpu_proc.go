package collector

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CPUCollector lê /proc/<pid>/stat polling a cada 500ms para calcular % de uso
// de CPU do processo via delta de (utime+stime) entre amostras.
//
// Funciona sem root, sem eBPF. Em macOS/Windows o Start falha silenciosamente
// porque /proc não existe — o model continua usando dados simulados.
type CPUCollector struct {
	pid  int
	ch   chan interface{}
	stop chan struct{}
	mu   sync.Mutex

	lastTicks    uint64
	lastSampleAt time.Time
}

func NewCPUCollector() *CPUCollector {
	return &CPUCollector{
		ch:   make(chan interface{}, 16),
		stop: make(chan struct{}),
	}
}

func (c *CPUCollector) Start(pid int) error {
	c.pid = pid
	if _, err := os.Stat(fmt.Sprintf("/proc/%d/stat", pid)); err != nil {
		return fmt.Errorf("processo %d não encontrado: %w", pid, err)
	}
	go c.loop()
	return nil
}

func (c *CPUCollector) Stop()                          { close(c.stop) }
func (c *CPUCollector) Subscribe() <-chan interface{}  { return c.ch }

func (c *CPUCollector) loop() {
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

// clkTck é a frequência do relógio do kernel (CONFIG_HZ), em ticks/segundo.
// Varia por arquitetura/distro:
//   - x86/x86_64: tipicamente 100 (Ubuntu) ou 250 (RHEL family)
//   - ARM/ARM64:  tipicamente 250 (Ubuntu/Debian) ou 1000 (Fedora ARM)
//
// Detecção via `getconf CLK_TCK` (POSIX, disponível em Linux e Darwin) —
// uma única invocação no startup, custo desprezível. Antes era hardcoded em
// 100, o que dava CPU% 2.5x errado em ARM (issue #18 follow-up).
var clkTck float64 = detectClkTck()

func detectClkTck() float64 {
	out, err := exec.Command("getconf", "CLK_TCK").Output()
	if err == nil {
		if v, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64); err == nil && v > 0 {
			return v
		}
	}
	return 100 // fallback razoável
}

func (c *CPUCollector) sample() (CpuSample, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", c.pid))
	if err != nil {
		return CpuSample{}, err
	}
	utime, stime, _, _, _, err := parseProcStatTimes(data)
	if err != nil {
		return CpuSample{}, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	totalTicks := utime + stime

	var pct float64
	if !c.lastSampleAt.IsZero() {
		elapsed := now.Sub(c.lastSampleAt).Seconds()
		if elapsed > 0 {
			deltaTicks := float64(totalTicks - c.lastTicks)
			// % single-core: deltaTicks/clkTck = segundos de CPU usados
			// dividido por elapsed = fração do tempo. ×100 = %.
			pct = (deltaTicks / clkTck) / elapsed * 100
		}
	}
	c.lastTicks = totalTicks
	c.lastSampleAt = now

	return CpuSample{
		UsagePct:  pct,
		Timestamp: now,
	}, nil
}

// parseProcStatTimes extrai campos numéricos chave de /proc/<pid>/stat.
//
// O campo 2 (comm) é parentesizado e PODE conter espaços/parens — o parser
// canônico procura o ÚLTIMO `)` na linha; o que vem depois são os campos 3..N
// space-separated. Index do post (post[i] = campo i+3):
//
//	post[7]  = minflt              (campo 10)
//	post[9]  = majflt              (campo 12)
//	post[11] = utime               (campo 14)
//	post[12] = stime               (campo 15)
//	post[39] = delayacct_blkio_ticks (campo 42)
//
// `blkio` retorna 0 se o kernel não exporta o campo (CONFIG_TASK_DELAY_ACCT
// off, ou kernel 5.14+ sem boot param `delayacct=on`).
func parseProcStatTimes(data []byte) (utime, stime, minflt, majflt, blkio uint64, err error) {
	s := string(data)
	end := strings.LastIndex(s, ")")
	if end < 0 {
		return 0, 0, 0, 0, 0, fmt.Errorf("malformed /proc stat: ')' ausente")
	}
	fields := strings.Fields(strings.TrimSpace(s[end+1:]))
	if len(fields) < 13 {
		return 0, 0, 0, 0, 0, fmt.Errorf("malformed /proc stat: %d campos", len(fields))
	}
	utime, _ = strconv.ParseUint(fields[11], 10, 64)
	stime, _ = strconv.ParseUint(fields[12], 10, 64)
	minflt, _ = strconv.ParseUint(fields[7], 10, 64)
	majflt, _ = strconv.ParseUint(fields[9], 10, 64)
	if len(fields) > 39 {
		blkio, _ = strconv.ParseUint(fields[39], 10, 64)
	}
	return
}
