//go:build linux && ebpf

package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/trentas/xray/internal/bpf"
)

// ThreadsEBPFCollector é um collector híbrido /proc + eBPF:
//
//   - /proc/<pid>/task/<tid>/{stat,wchan} → state textual, comm, wchan
//     (informação que só /proc tem em formato canônico)
//   - eBPF tid_state via tracepoint sched:sched_switch → CPU% baseado em
//     on-CPU time real + contagem de context switches por TID na janela
//
// Resultado: ThreadInfo com tudo que o /proc dava + ctx_switches da
// janela + CPU% mais preciso (window-based em vez de cumulativo).
//
// Lifecycle:
//   - tick a cada 1s
//   - lê /proc/<pid>/task/ → coleta state/wchan/name + lista de TIDs vivos
//   - sincroniza tracked_tids no BPF map (add novos, remove órfãos)
//   - lê tid_state do BPF, calcula deltas vs snapshot anterior
//   - publica []ThreadInfo
type ThreadsEBPFCollector struct {
	tracer *bpf.ThreadsTracer
	pid    int
	ch     chan interface{}
	stop   chan struct{}

	mu          sync.Mutex
	prevOnNs    map[uint32]uint64 // tid → on_cpu_ns_total na última amostra
	prevSwitch  map[uint32]uint64 // tid → ctx_switches na última amostra
	lastSampleAt time.Time
}

func NewThreadsEBPFCollector() *ThreadsEBPFCollector {
	return &ThreadsEBPFCollector{
		ch:         make(chan interface{}, 4),
		stop:       make(chan struct{}),
		prevOnNs:   make(map[uint32]uint64),
		prevSwitch: make(map[uint32]uint64),
	}
}

func (c *ThreadsEBPFCollector) Start(pid int) error {
	if _, err := os.Stat(fmt.Sprintf("/proc/%d/task", pid)); err != nil {
		return fmt.Errorf("processo %d não encontrado: %w", pid, err)
	}
	tracer, err := bpf.OpenThreadsTracer(pid)
	if err != nil {
		return fmt.Errorf("threads eBPF: %w", err)
	}
	c.tracer = tracer
	c.pid = pid
	go c.loop()
	return nil
}

func (c *ThreadsEBPFCollector) Stop() {
	close(c.stop)
	if c.tracer != nil {
		_ = c.tracer.Close()
		c.tracer = nil
	}
}

func (c *ThreadsEBPFCollector) Subscribe() <-chan interface{} {
	return c.ch
}

func (c *ThreadsEBPFCollector) loop() {
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

func (c *ThreadsEBPFCollector) collect() ([]ThreadInfo, error) {
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

	// 1ª passada: lê /proc/task/* e monta lista de TIDs + metadata.
	type procData struct {
		comm    string
		state   byte
		wchan   string
	}
	procByTID := make(map[uint32]procData, len(entries))
	tidList := make([]int, 0, len(entries))
	for _, e := range entries {
		tid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		statData, err := os.ReadFile(filepath.Join(taskDir, e.Name(), "stat"))
		if err != nil {
			continue
		}
		comm, state, _, ok := parseThreadStat(statData)
		if !ok {
			continue
		}
		wchan := ""
		if w, err := os.ReadFile(filepath.Join(taskDir, e.Name(), "wchan")); err == nil {
			wchan = strings.TrimSpace(string(w))
			if wchan == "0" {
				wchan = ""
			}
		}
		procByTID[uint32(tid)] = procData{comm: comm, state: state, wchan: wchan}
		tidList = append(tidList, tid)
	}

	// Sincroniza tracked_tids no BPF map.
	if err := c.tracer.UpdateTrackedTIDs(tidList); err != nil {
		// Não fatal: continua publicando dados de /proc mesmo se o sync falhar.
		_ = err
	}

	// 2ª passada: lê tid_state e calcula deltas.
	stats, err := c.tracer.Stats()
	if err != nil {
		stats = nil
	}

	out := make([]ThreadInfo, 0, len(procByTID))
	for tid, pd := range procByTID {
		s := stats[tid]
		var cpuPct float64
		var switches uint64

		if elapsed > 0 {
			deltaOn := s.OnCpuNsTotal - c.prevOnNs[tid]
			cpuPct = (float64(deltaOn) / 1e9) / elapsed * 100
			if cpuPct > 100 {
				cpuPct = 100 // ceil — multi-core single thread não passa de 100%
			}
			switches = s.CtxSwitches - c.prevSwitch[tid]
		}
		c.prevOnNs[tid] = s.OnCpuNsTotal
		c.prevSwitch[tid] = s.CtxSwitches

		out = append(out, ThreadInfo{
			TID:         int(tid),
			Name:        pd.comm,
			State:       mapThreadState(pd.state),
			CPUPct:      cpuPct,
			Waiting:     pd.wchan,
			CtxSwitches: switches,
		})
	}

	// Garbage collect prev maps de TIDs que sumiram.
	for tid := range c.prevOnNs {
		if _, alive := procByTID[tid]; !alive {
			delete(c.prevOnNs, tid)
			delete(c.prevSwitch, tid)
		}
	}

	c.lastSampleAt = now
	return out, nil
}
