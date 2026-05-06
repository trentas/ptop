//go:build linux && ebpf

package collector

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/trentas/xray/internal/bpf"
)

// FutexEBPFCollector consome o map futex_stats periodicamente e publica
// um []LockEntry ranqueado por contestação na janela atual (delta de
// waits no último intervalo). Emite TimelineEvent category="lock"
// quando algum uaddr passa do threshold de contestação no intervalo.
type FutexEBPFCollector struct {
	tracer *bpf.FutexTracer
	ch     chan interface{}
	stop   chan struct{}

	mu   sync.Mutex
	prev map[uint64]bpf.FutexStat
}

// contentionThreshold define quantos novos waits no intervalo (1s) são
// suficientes pra gerar um TimelineEvent. Valor pequeno o bastante pra
// detectar locks problemáticos, grande o bastante pra ignorar mutexes
// "ok" que travam ocasionalmente.
const contentionThreshold = 20

// topLockEntries é quantas linhas o LockGraph publica. F4 tem espaço
// pequeno; manter compacto.
const topLockEntries = 8

func NewFutexEBPFCollector() *FutexEBPFCollector {
	return &FutexEBPFCollector{
		ch:   make(chan interface{}, 8),
		stop: make(chan struct{}),
		prev: make(map[uint64]bpf.FutexStat),
	}
}

func (c *FutexEBPFCollector) Start(pid int) error {
	tracer, err := bpf.OpenFutexTracer(pid)
	if err != nil {
		return fmt.Errorf("futex eBPF: %w", err)
	}
	c.tracer = tracer
	go c.loop()
	return nil
}

func (c *FutexEBPFCollector) Stop() {
	close(c.stop)
	if c.tracer != nil {
		_ = c.tracer.Close()
		c.tracer = nil
	}
}

func (c *FutexEBPFCollector) Subscribe() <-chan interface{} {
	return c.ch
}

func (c *FutexEBPFCollector) loop() {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			snap, hot := c.snapshot()
			select {
			case c.ch <- snap:
			default:
			}
			// Eventos de timeline: um por uaddr "quente" no intervalo.
			// Limita a 3 por tick pra não inundar.
			emitted := 0
			for _, e := range hot {
				if emitted >= 3 {
					break
				}
				select {
				case c.ch <- TimelineEvent{
					Timestamp: time.Now(),
					Category:  "lock",
					Message: fmt.Sprintf(
						"futex@0x%x ↑ %d waits (avg %.1fms, last tid %d)",
						e.UAddr, e.WaitDelta, e.LatencyMs, e.LastWaitTID,
					),
				}:
					emitted++
				default:
				}
			}
		}
	}
}

// snapshot lê futex_stats, calcula delta vs prev, devolve top-N por
// contestação na janela e a lista "hot" (passou do threshold pra emitir
// timeline).
func (c *FutexEBPFCollector) snapshot() (snap []LockEntry, hot []LockEntry) {
	if c.tracer == nil {
		return nil, nil
	}
	stats, err := c.tracer.Stats()
	if err != nil {
		return nil, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	all := make([]LockEntry, 0, len(stats))
	for uaddr, s := range stats {
		p := c.prev[uaddr]
		waitDelta := s.WaitCount - p.WaitCount
		latMs := 0.0
		if s.LatCount > 0 {
			latMs = float64(s.LatSumNs) / float64(s.LatCount) / 1e6
		}
		entry := LockEntry{
			UAddr:       uaddr,
			Waiters:     s.WaitCount,
			Wakers:      s.WakeCount,
			WaitDelta:   waitDelta,
			LatencyMs:   latMs,
			LastWaitTID: int(s.LastWaitTID),
			LastWakeTID: int(s.LastWakeTID),
		}
		all = append(all, entry)
		if waitDelta >= contentionThreshold {
			hot = append(hot, entry)
		}
	}
	c.prev = stats

	// Ranking: por WaitDelta desc, com Waiters total como desempate.
	sort.Slice(all, func(i, j int) bool {
		if all[i].WaitDelta != all[j].WaitDelta {
			return all[i].WaitDelta > all[j].WaitDelta
		}
		return all[i].Waiters > all[j].Waiters
	})
	if len(all) > topLockEntries {
		all = all[:topLockEntries]
	}
	// Hot lista também ordenada por delta desc.
	sort.Slice(hot, func(i, j int) bool {
		return hot[i].WaitDelta > hot[j].WaitDelta
	})
	return all, hot
}
