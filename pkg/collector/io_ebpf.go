//go:build linux && ebpf

package collector

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/trentas/ptop/internal/bpf"
)

// IOEBPFCollector consumes the event ring buffer of the eBPF I/O tracer
// and aggregates by PATH in 500ms windows. Output is the IOStats.TopFiles +
// LatencyBuckets, updated and published over the channel.
//
// A file is named as it was when the call ran, from the open that installed
// its fd or from the fd's link checked against the event's inode (fileNames,
// #162). One it cannot name is "fd=N".
type IOEBPFCollector struct {
	tracer *bpf.IOTracer
	ch     chan interface{}
	stop   chan struct{}
	pid    int
	names  *fileNames // read loop only

	mu      sync.Mutex
	files   map[string]*ioFileAgg // path → counters
	buckets []LatencyBucket       // pre-built baseline buckets
}

type ioFileAgg struct {
	reads    uint64
	writes   uint64
	bytes    uint64
	latSumNs uint64
	latCount uint64
	latMaxNs uint64
	fileType string
}

func NewIOEBPFCollector() *IOEBPFCollector {
	return &IOEBPFCollector{
		// Buffered for the 500ms snapshot ticker plus bursty per-event fs
		// events (#57); all senders drop on overflow.
		ch:    make(chan interface{}, 64),
		stop:  make(chan struct{}),
		files: make(map[string]*ioFileAgg),
		buckets: []LatencyBucket{
			{Label: "<0.1ms"},
			{Label: "0.1-1ms"},
			{Label: "1-5ms"},
			{Label: "5-20ms"},
			{Label: ">20ms"},
		},
	}
}

func (c *IOEBPFCollector) Start(pid int) error { return c.start(bpf.TargetPID(pid), pid) }

// StartCgroup tracks I/O across a whole cgroup subtree instead of one pid
// (#94). Implements CgroupTargeter.
//
// Byte counters and latency histograms are unaffected, but top files are named
// "fd=N": naming one means reading /proc/<pid>/fd/<n>, and a subtree has no
// single pid to read it from (fileNames).
func (c *IOEBPFCollector) StartCgroup(spec string) error {
	return c.start(bpf.TargetCgroup(spec), 0)
}

func (c *IOEBPFCollector) start(t bpf.Target, pid int) error {
	tracer, err := bpf.OpenIOTracer(t)
	if err != nil {
		return fmt.Errorf("io eBPF: %w", err)
	}
	c.tracer = tracer
	c.pid = pid
	c.names = newFileNames(pid)
	go c.readLoop()    // consumes io_events ringbuf, populates c.files
	go c.publishLoop() // every 500ms publishes a snapshot of the aggregates
	// Drain fs-semantics events (#57). tracer is passed explicitly (not read
	// from the field) so Stop()'s `c.tracer = nil` can't race this goroutine;
	// Close() shuts the fs ring-buffer reader, unblocking NextFSEvent with io.EOF.
	go c.fsReadLoop(tracer)
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

// readLoop reads events from the ring buffer indefinitely, updating
// aggregates in place. Ringbuf.Read blocks until an event arrives — when
// the tracer closes, it returns io.EOF and the goroutine exits.
func (c *IOEBPFCollector) readLoop() {
	for {
		ev, err := c.tracer.Next()
		if err != nil {
			if err == io.EOF {
				return
			}
			// transient error; try again
			continue
		}
		c.processEvent(ev)
	}
}

// fsReadLoop drains the fs-semantics ring buffer (#57), decoding each record
// into an FSEvent and publishing it on the shared channel. It exits on io.EOF
// (the tracer was closed). A garbled record is logged-by-skip — the stream
// continues. Sends are non-blocking: under backpressure fs events are dropped,
// consistent with every other collector.
func (c *IOEBPFCollector) fsReadLoop(tracer *bpf.IOTracer) {
	if tracer == nil {
		return
	}
	for {
		rec, err := tracer.NextFSEvent()
		if err != nil {
			if err == io.EOF {
				return
			}
			continue // transient (short/garbled record) — keep reading
		}
		fe := decodeFSEvent(time.Now(), rec.Op, rec.Ret, rec.Path[:], rec.NewPath[:])
		publish(c.ch, fe)
	}
}

func (c *IOEBPFCollector) processEvent(ev bpf.IOEvent) {
	now := time.Now()
	if ev.Op == bpf.IOOpOpen {
		c.names.opened(ev.FD, ev.Ino, ev.Dfd, ev.Path, now)
		return
	}
	path := c.names.name(ev.FD, ev.Ino, now)
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

	// Latency histogram (in ms)
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

// publishLoop snapshots the aggregates every 500ms and publishes a partial
// IOStats. Histogram resets every publish — buckets reflect the current
// window, not cumulative (more useful for the UI). TopFiles remain
// cumulative (consistent with /proc/<pid>/io which is cumulative).
func (c *IOEBPFCollector) publishLoop() {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			snap := c.snapshot()
			publish(c.ch, snap)
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
			Fsyncs:    0, // no fsync tracking yet
		})
	}

	// Copy buckets and reset the cumulative
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

// IOEBPFSnapshot is the published payload. Model updates IOStats.TopFiles
// and IOStats.LatencyBuckets from this.
type IOEBPFSnapshot struct {
	TopFiles []IOFileStats
	Buckets  []LatencyBucket
}

// classifyPath: type heuristic to color the type in F5.
// Stays compatible with the mockup: db / log / cfg / tmp / proc / file / sock.
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
		// Resolve absolute if path is relative (rare case, defensive)
		if !filepath.IsAbs(p) {
			return "file"
		}
		return "file"
	}
}

// bucketIndexMs maps latency in ms to the right histogram bucket.
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
