//go:build linux && ebpf

package collector

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/trentas/xray/internal/bpf"
)

// IOEBPFCollector consome o ring buffer de eventos do tracer eBPF de I/O
// e agrega por PATH em janelas de 500ms. Output é o IOStats.TopFiles +
// LatencyBuckets atualizados, publicados via canal.
//
// Resolução fd→path: lookup em /proc/<pid>/fd/<fd> readlink, com cache
// de 2s pra reduzir overhead. FDs novos resolvem na primeira aparição.
type IOEBPFCollector struct {
	tracer *bpf.IOTracer
	ch     chan interface{}
	stop   chan struct{}
	pid    int

	mu      sync.Mutex
	files   map[string]*ioFileAgg     // path → contadores
	pathFor map[uint32]pathCacheEntry // fd → path (cached)
	buckets []LatencyBucket           // baseline buckets pré-criados
}

type ioFileAgg struct {
	reads     uint64
	writes    uint64
	bytes     uint64
	latSumNs  uint64
	latCount  uint64
	latMaxNs  uint64
	fileType  string
}

type pathCacheEntry struct {
	path  string
	at    time.Time
}

const ioPathCacheTTL = 2 * time.Second

func NewIOEBPFCollector() *IOEBPFCollector {
	return &IOEBPFCollector{
		ch:      make(chan interface{}, 16),
		stop:    make(chan struct{}),
		files:   make(map[string]*ioFileAgg),
		pathFor: make(map[uint32]pathCacheEntry),
		buckets: []LatencyBucket{
			{Label: "<0.1ms"},
			{Label: "0.1-1ms"},
			{Label: "1-5ms"},
			{Label: "5-20ms"},
			{Label: ">20ms"},
		},
	}
}

func (c *IOEBPFCollector) Start(pid int) error {
	tracer, err := bpf.OpenIOTracer(pid)
	if err != nil {
		return fmt.Errorf("io eBPF: %w", err)
	}
	c.tracer = tracer
	c.pid = pid
	go c.readLoop()    // consome ringbuf, popula c.files
	go c.publishLoop() // a cada 500ms publica snapshot dos agregados
	return nil
}

func (c *IOEBPFCollector) Stop() {
	close(c.stop)
	if c.tracer != nil {
		_ = c.tracer.Close()
		c.tracer = nil
	}
}

func (c *IOEBPFCollector) Subscribe() <-chan interface{} {
	return c.ch
}

// readLoop lê eventos da ring buffer indefinidamente, atualiza agregados
// in-place. Ringbuf.Read bloqueia até evento chegar — quando o tracer
// fecha, retorna io.EOF e a goroutine termina.
func (c *IOEBPFCollector) readLoop() {
	for {
		ev, err := c.tracer.Next()
		if err != nil {
			if err == io.EOF {
				return
			}
			// erro transiente; tenta de novo
			continue
		}
		c.processEvent(ev)
	}
}

func (c *IOEBPFCollector) processEvent(ev bpf.IOEvent) {
	path := c.resolvePath(ev.FD)
	if path == "" {
		path = fmt.Sprintf("fd=%d", ev.FD)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	agg, ok := c.files[path]
	if !ok {
		agg = &ioFileAgg{fileType: classifyPath(path)}
		c.files[path] = agg
	}
	if ev.Op == bpf.IOOpRead {
		agg.reads++
	} else {
		agg.writes++
	}
	agg.bytes += ev.Bytes
	agg.latSumNs += ev.LatNs
	agg.latCount++
	if ev.LatNs > agg.latMaxNs {
		agg.latMaxNs = ev.LatNs
	}

	// Histograma de latência (em ms)
	latMs := float64(ev.LatNs) / 1e6
	bIdx := bucketIndexMs(latMs)
	if bIdx >= 0 && bIdx < len(c.buckets) {
		if ev.Op == bpf.IOOpRead {
			c.buckets[bIdx].Read++
		} else {
			c.buckets[bIdx].Write++
		}
	}
}

// resolvePath lê /proc/<pid>/fd/<fd> via readlink, com cache de 2s.
// Sockets e pipes retornam paths como "socket:[N]" — caller deve filtrar
// se quiser só files de verdade. Aqui mantemos tudo (sockets aparecem
// como "socket:[12345]" no top files, sinalizando network I/O).
func (c *IOEBPFCollector) resolvePath(fd uint32) string {
	c.mu.Lock()
	if cached, ok := c.pathFor[fd]; ok && time.Since(cached.at) < ioPathCacheTTL {
		c.mu.Unlock()
		return cached.path
	}
	c.mu.Unlock()

	link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", c.pid, fd))
	if err != nil {
		return ""
	}

	c.mu.Lock()
	c.pathFor[fd] = pathCacheEntry{path: link, at: time.Now()}
	c.mu.Unlock()
	return link
}

// publishLoop a cada 500ms snapshota os agregados e publica IOStats parcial.
// Reset do histograma a cada publish — buckets refletem janela atual,
// não cumulativo (mais útil pra UI). TopFiles permanecem cumulativos
// (consistente com /proc/<pid>/io que cumula).
func (c *IOEBPFCollector) publishLoop() {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			snap := c.snapshot()
			select {
			case c.ch <- snap:
			default:
			}
		}
	}
}

func (c *IOEBPFCollector) snapshot() IOEBPFSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	files := make([]IOFileStats, 0, len(c.files))
	for path, agg := range c.files {
		latAvgMs := 0.0
		if agg.latCount > 0 {
			latAvgMs = float64(agg.latSumNs) / float64(agg.latCount) / 1e6
		}
		files = append(files, IOFileStats{
			Path:      path,
			Type:      agg.fileType,
			Reads:     agg.reads,
			Writes:    agg.writes,
			Bytes:     agg.bytes,
			LatencyMs: latAvgMs,
			Fsyncs:    0, // sem fsync tracking ainda
		})
	}

	// Copia buckets e reseta o cumulativo
	bucketsCopy := append([]LatencyBucket(nil), c.buckets...)
	for i := range c.buckets {
		c.buckets[i].Read = 0
		c.buckets[i].Write = 0
	}

	return IOEBPFSnapshot{
		TopFiles: files,
		Buckets:  bucketsCopy,
	}
}

// IOEBPFSnapshot é o payload publicado. Model atualiza IOStats.TopFiles
// e IOStats.LatencyBuckets a partir disso.
type IOEBPFSnapshot struct {
	TopFiles []IOFileStats
	Buckets  []LatencyBucket
}

// classifyPath: heurística de tipo pra colorir o tipo na F5.
// Mantém compatível com mockup: db / log / cfg / tmp / proc / file / sock.
func classifyPath(p string) string {
	switch {
	case strings.HasPrefix(p, "socket:"):
		return "sock"
	case strings.HasPrefix(p, "pipe:"):
		return "pipe"
	case strings.HasPrefix(p, "anon_inode:"):
		return "anon"
	case strings.Contains(p, "/proc/"):
		return "proc"
	case strings.Contains(p, "/tmp/"):
		return "tmp"
	case strings.HasSuffix(p, ".log") || strings.Contains(p, "/log/"):
		return "log"
	case strings.HasSuffix(p, ".db") || strings.HasSuffix(p, ".sqlite") ||
		strings.Contains(p, "/db/") || strings.HasSuffix(p, ".db-shm") ||
		strings.HasSuffix(p, ".db-wal"):
		return "db"
	case strings.HasSuffix(p, ".json") || strings.HasSuffix(p, ".yaml") ||
		strings.HasSuffix(p, ".toml") || strings.HasSuffix(p, ".conf") ||
		strings.HasSuffix(p, ".ini") || strings.HasSuffix(p, ".cfg") ||
		strings.Contains(p, "/etc/"):
		return "cfg"
	default:
		// Resolve absoluto se path é relativo (caso raro, defesa)
		if !filepath.IsAbs(p) {
			return "file"
		}
		return "file"
	}
}

// bucketIndexMs mapeia latência em ms pro bucket certo do histograma.
// Buckets: <0.1, 0.1-1, 1-5, 5-20, >20.
func bucketIndexMs(ms float64) int {
	switch {
	case ms < 0.1:
		return 0
	case ms < 1:
		return 1
	case ms < 5:
		return 2
	case ms < 20:
		return 3
	default:
		return 4
	}
}
