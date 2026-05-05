package collector

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MemCollector lê /proc/<pid>/statm + /proc/<pid>/stat a cada 1s para popular
// RSS, heap aproximado, page faults acumulados e taxa de allocs/s estimada
// (usa total de page faults como proxy — não é perfeito mas é o melhor que
// /proc oferece sem instrumentação).
type MemCollector struct {
	pid  int
	ch   chan interface{}
	stop chan struct{}
	mu   sync.Mutex

	lastFaults uint64
	lastAt     time.Time
}

func NewMemCollector() *MemCollector {
	return &MemCollector{
		ch:   make(chan interface{}, 16),
		stop: make(chan struct{}),
	}
}

func (c *MemCollector) Start(pid int) error {
	c.pid = pid
	if _, err := os.Stat(fmt.Sprintf("/proc/%d/statm", pid)); err != nil {
		return fmt.Errorf("processo %d não encontrado: %w", pid, err)
	}
	go c.loop()
	return nil
}

func (c *MemCollector) Stop()                          { close(c.stop) }
func (c *MemCollector) Subscribe() <-chan interface{}  { return c.ch }

func (c *MemCollector) loop() {
	t := time.NewTicker(1 * time.Second)
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

func (c *MemCollector) sample() (MemStats, error) {
	// /proc/<pid>/statm: size resident shared text lib data dirty (em pages)
	statmData, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", c.pid))
	if err != nil {
		return MemStats{}, err
	}
	fields := strings.Fields(string(statmData))
	if len(fields) < 7 {
		return MemStats{}, fmt.Errorf("malformed /proc/.../statm: %d campos", len(fields))
	}
	pageSize := uint64(os.Getpagesize())
	resident, _ := strconv.ParseUint(fields[1], 10, 64)
	dataPages, _ := strconv.ParseUint(fields[5], 10, 64)

	// page faults via /proc/<pid>/stat (campos minflt+majflt)
	statData, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", c.pid))
	if err != nil {
		return MemStats{}, err
	}
	_, _, minflt, majflt, _, _ := parseProcStatTimes(statData)
	totalFaults := minflt + majflt

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var allocsPerS uint64
	if !c.lastAt.IsZero() {
		elapsed := now.Sub(c.lastAt).Seconds()
		if elapsed > 0 && totalFaults >= c.lastFaults {
			allocsPerS = uint64(float64(totalFaults-c.lastFaults) / elapsed)
		}
	}
	c.lastFaults = totalFaults
	c.lastAt = now

	return MemStats{
		RSSBytes:   resident * pageSize,
		HeapBytes:  dataPages * pageSize, // aproximação: data segment ~ heap+anon mappings
		PageFaults: totalFaults,
		AllocsPerS: allocsPerS,
	}, nil
}
