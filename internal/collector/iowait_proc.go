package collector

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// IOWaitCollector lê /proc/<pid>/stat campo 42 (delayacct_blkio_ticks)
// e converte em % do wallclock que o processo passou bloqueado em block I/O
// síncrono no último intervalo.
//
// Esta é a fonte canônica para "este processo está esperando disco?" — o
// `iowait` global de top/vmstat é uma estatística system-wide de CPU ociosa,
// NÃO atribuível a um PID. delayacct_blkio_ticks é per-task e exato.
//
// Requer kernel com CONFIG_TASK_DELAY_ACCT (default em distros modernas).
// Em kernels 5.14+ pode requerer boot param `delayacct=on`. Quando o kernel
// não exporta o campo, parseProcStatTimes retorna blkio=0 sem erro — o
// collector continua publicando 0%, sinalizando "sem dados".
type IOWaitCollector struct {
	pid  int
	ch   chan interface{}
	stop chan struct{}
	mu   sync.Mutex

	lastBlkio uint64
	lastAt    time.Time
}

func NewIOWaitCollector() *IOWaitCollector {
	return &IOWaitCollector{
		ch:   make(chan interface{}, 16),
		stop: make(chan struct{}),
	}
}

func (c *IOWaitCollector) Start(pid int) error {
	c.pid = pid
	if _, err := os.Stat(fmt.Sprintf("/proc/%d/stat", pid)); err != nil {
		return fmt.Errorf("processo %d não encontrado: %w", pid, err)
	}
	go c.loop()
	return nil
}

func (c *IOWaitCollector) Stop()                          { close(c.stop) }
func (c *IOWaitCollector) Subscribe() <-chan interface{}  { return c.ch }

func (c *IOWaitCollector) loop() {
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

func (c *IOWaitCollector) sample() (IOWaitSample, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", c.pid))
	if err != nil {
		return IOWaitSample{}, err
	}
	_, _, _, _, blkio, err := parseProcStatTimes(data)
	if err != nil {
		return IOWaitSample{}, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var pct float64
	if !c.lastAt.IsZero() {
		elapsed := now.Sub(c.lastAt).Seconds()
		if elapsed > 0 && blkio >= c.lastBlkio {
			deltaTicks := float64(blkio - c.lastBlkio)
			// % do wallclock: deltaTicks/clkTck = segundos esperando I/O.
			// Dividido por elapsed = fração; ×100 = %.
			pct = (deltaTicks / clkTck) / elapsed * 100
			if pct > 100 {
				pct = 100 // saturação multi-thread em rare cases
			}
		}
	}
	c.lastBlkio = blkio
	c.lastAt = now

	return IOWaitSample{
		Pct:       pct,
		Timestamp: now,
	}, nil
}
