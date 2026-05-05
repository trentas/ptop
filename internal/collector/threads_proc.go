package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ThreadsCollector enumera /proc/<pid>/task/* a cada 1s e produz []ThreadInfo
// com state, CPU% (via delta de utime+stime) e wchan (kernel function em que
// está bloqueada).
type ThreadsCollector struct {
	pid  int
	ch   chan interface{}
	stop chan struct{}
	mu   sync.Mutex

	prev         map[int]uint64 // tid → totalTicks
	lastSampleAt time.Time
}

func NewThreadsCollector() *ThreadsCollector {
	return &ThreadsCollector{
		ch:   make(chan interface{}, 16),
		stop: make(chan struct{}),
		prev: make(map[int]uint64),
	}
}

func (c *ThreadsCollector) Start(pid int) error {
	c.pid = pid
	if _, err := os.Stat(fmt.Sprintf("/proc/%d/task", pid)); err != nil {
		return fmt.Errorf("processo %d não encontrado: %w", pid, err)
	}
	go c.loop()
	return nil
}

func (c *ThreadsCollector) Stop()                          { close(c.stop) }
func (c *ThreadsCollector) Subscribe() <-chan interface{}  { return c.ch }

func (c *ThreadsCollector) loop() {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			if threads, err := c.collect(); err == nil {
				select {
				case c.ch <- threads:
				default:
				}
			}
		}
	}
}

func mapThreadState(c byte) string {
	switch c {
	case 'R':
		return "running"
	case 'D':
		return "blocked"
	case 'S', 'I':
		return "sleeping"
	case 'Z', 'T', 't':
		return "stopped"
	default:
		return "unknown"
	}
}

func (c *ThreadsCollector) collect() ([]ThreadInfo, error) {
	taskDir := fmt.Sprintf("/proc/%d/task", c.pid)
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	elapsed := 0.0
	if !c.lastSampleAt.IsZero() {
		elapsed = now.Sub(c.lastSampleAt).Seconds()
	}

	seen := make(map[int]bool, len(entries))
	out := make([]ThreadInfo, 0, len(entries))

	for _, e := range entries {
		tid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		seen[tid] = true

		statData, err := os.ReadFile(filepath.Join(taskDir, e.Name(), "stat"))
		if err != nil {
			continue
		}

		comm, state, totalTicks, ok := parseThreadStat(statData)
		if !ok {
			continue
		}

		var cpuPct float64
		if prev, hadPrev := c.prev[tid]; hadPrev && elapsed > 0 {
			delta := float64(totalTicks - prev)
			cpuPct = (delta / clkTck) / elapsed * 100
		}
		c.prev[tid] = totalTicks

		// wchan = kernel function em que está dormindo (vazio se running)
		wchan := ""
		if w, err := os.ReadFile(filepath.Join(taskDir, e.Name(), "wchan")); err == nil {
			wchan = strings.TrimSpace(string(w))
			if wchan == "0" {
				wchan = ""
			}
		}

		out = append(out, ThreadInfo{
			TID:     tid,
			Name:    comm,
			State:   mapThreadState(state),
			CPUPct:  cpuPct,
			Waiting: wchan,
		})
	}

	// purga cache de threads que sumiram
	for tid := range c.prev {
		if !seen[tid] {
			delete(c.prev, tid)
		}
	}

	c.lastSampleAt = now
	return out, nil
}

// parseThreadStat extrai (comm, state, utime+stime) de /proc/<pid>/task/<tid>/stat.
// Mesmo cuidado com o `)` final do campo comm que em parseProcStatTimes.
func parseThreadStat(data []byte) (comm string, state byte, totalTicks uint64, ok bool) {
	s := string(data)
	commStart := strings.Index(s, "(")
	commEnd := strings.LastIndex(s, ")")
	if commStart < 0 || commEnd < 0 || commEnd <= commStart {
		return "", 0, 0, false
	}
	comm = s[commStart+1 : commEnd]
	fields := strings.Fields(strings.TrimSpace(s[commEnd+1:]))
	if len(fields) < 13 || len(fields[0]) == 0 {
		return "", 0, 0, false
	}
	state = fields[0][0]
	utime, _ := strconv.ParseUint(fields[11], 10, 64)
	stime, _ := strconv.ParseUint(fields[12], 10, 64)
	return comm, state, utime + stime, true
}
