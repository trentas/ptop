//go:build linux

package collector

import (
	"fmt"
	"strings"
	"time"

	"github.com/trentas/ptop/internal/bpf"
)

// ioAgg turns the io probe's counts into IOEBPFSnapshots (#181).
//
// The kernel counts reads and writes per key — (tgid, fd, inode) — in
// io_stats, and the latency histogram per CPU in io_totals. The collector
// reads both every window and adds what each key gained to its file's row.
// It used to receive one ring record per call and count them itself, which
// cost a syscall-bound target 4-5x its throughput.
//
// The ring still brings what has to be learned when it happens:
//   - the open that names a file (#162);
//   - a key's first call, named then, before its fd can be closed;
//   - a key's final counts when the target closes its fd. The kernel deletes
//     the key there, so io_stats holds the files open with I/O, not every file
//     the target ever touched.
//
// A key can live several lives: a file closed and opened again on the same fd
// number gets the same (fd, inode) back. gen, when the kernel created the
// entry, tells them apart, so one life's counts are never diffed against
// another's. Within a life every counter only grows; a high-water mark per
// counter absorbs a read that caught one counter a call ahead of another.
//
// Not safe for concurrent use: the collector's loop is its only caller.
type ioAgg struct {
	names *fileNames
	lives map[ioLife]*ioLifeState
	// closed holds the lives whose final counts came in a close record, for a
	// map read that lands between the record and the delete right after it.
	closed map[ioLife]time.Time
	files  map[string]*ioFileAgg
	hist   [2][bpf.IOBuckets]uint64 // the kernel's cumulative histogram, as last read
	lost   bpf.IOTotals             // its lost_* counts, as last read
	round  uint64                   // map reads so far
}

type ioLife struct {
	key bpf.IOKey
	gen uint64
}

type ioLifeState struct {
	path  string
	last  bpf.IOStat // counts added to the row so far
	moved time.Time  // when they last grew
	round uint64     // the last map read the key was in
}

type ioFileAgg struct {
	reads    uint64
	writes   uint64
	bytes    uint64
	latSumNs uint64
	fileType string
}

const (
	// ioIdleRetire: a key unchanged this long is deleted by the collector, with
	// its counts added first. That covers fds closed without close(2) — dup2
	// over one, close_range, a process exiting in cgroup mode. A key retired
	// while still open is created again by its next call.
	ioIdleRetire = 30 * time.Second
	// ioClosedHold is how long a closed life is kept out of map reads.
	ioClosedHold = time.Second
)

func newIOAgg(pid int) *ioAgg {
	return &ioAgg{
		names:  newFileNames(pid),
		lives:  make(map[ioLife]*ioLifeState),
		closed: make(map[ioLife]time.Time),
		files:  make(map[string]*ioFileAgg),
	}
}

// record takes one ring record.
func (a *ioAgg) record(r bpf.IORecord, now time.Time) {
	switch r.Kind {
	case bpf.IORecOpen:
		a.names.opened(r.FD, r.Ino, r.Dfd, r.Path, now)
	case bpf.IORecSeen:
		a.life(ioLife{r.Key(), r.Gen}, now)
	case bpf.IORecClose:
		a.end(ioLife{r.Key(), r.Gen}, r.Stat, now)
	}
}

// read adds what one read of io_stats shows, and returns the keys idle for
// ioIdleRetire. The caller retires them (bpf.IOTracer.RetireStat) and hands
// what they held to retired.
//
// caughtUp says the ring was drained empty after the map was read. Until it
// has been, a key the ring has not announced is left alone: the open that
// names it may still be in the ring, and naming it now, from its fd's link,
// would read "fd=N" for a file already closed. Its first-call record names it
// later, and the next read or its close record counts it; nothing is lost.
func (a *ioAgg) read(stats map[bpf.IOKey]bpf.IOStat, now time.Time, caughtUp bool) []bpf.IOKey {
	a.round++
	var idle []bpf.IOKey
	for k, v := range stats {
		l := ioLife{k, v.Gen}
		if _, ok := a.closed[l]; ok {
			continue
		}
		if _, ok := a.lives[l]; !ok && !caughtUp {
			continue
		}
		st := a.life(l, now)
		st.round = a.round
		a.fold(st, v, now)
		if now.Sub(st.moved) >= ioIdleRetire {
			idle = append(idle, k)
		}
	}
	for l, st := range a.lives {
		// Missing from two reads with no close record: the record was lost to
		// a full ring, and with it the counts since the last read.
		if a.round-st.round >= 2 {
			delete(a.lives, l)
		}
	}
	for l, at := range a.closed {
		if now.Sub(at) > ioClosedHold {
			delete(a.closed, l)
		}
	}
	return idle
}

// retired adds what a retired key held.
func (a *ioAgg) retired(k bpf.IOKey, v bpf.IOStat, now time.Time) {
	a.end(ioLife{k, v.Gen}, v, now)
}

// end adds a life's final counts and forgets it.
func (a *ioAgg) end(l ioLife, final bpf.IOStat, now time.Time) {
	a.fold(a.life(l, now), final, now)
	delete(a.lives, l)
	a.closed[l] = now
}

// life is l's state, named when it is first seen.
func (a *ioAgg) life(l ioLife, now time.Time) *ioLifeState {
	if st, ok := a.lives[l]; ok {
		return st
	}
	path := a.names.name(l.key.FD, l.key.Ino, now)
	if path == "" {
		path = fmt.Sprintf("fd=%d", l.key.FD)
	}
	st := &ioLifeState{path: path, moved: now, round: a.round}
	a.lives[l] = st
	return st
}

// fold adds to the life's row what its counts gained since the last fold.
func (a *ioAgg) fold(st *ioLifeState, cur bpf.IOStat, now time.Time) {
	dr := grow(&st.last.Reads, cur.Reads)
	dw := grow(&st.last.Writes, cur.Writes)
	db := grow(&st.last.Bytes, cur.Bytes)
	dl := grow(&st.last.LatNs, cur.LatNs)
	if dr == 0 && dw == 0 && db == 0 && dl == 0 {
		return
	}
	st.moved = now
	f, ok := a.files[st.path]
	if !ok {
		f = &ioFileAgg{fileType: classifyPath(st.path)}
		a.files[st.path] = f
	}
	f.reads += dr
	f.writes += dw
	f.bytes += db
	f.latSumNs += dl
}

// grow moves a high-water mark to cur and returns how far it moved.
func grow(last *uint64, cur uint64) uint64 {
	if cur <= *last {
		return 0
	}
	d := cur - *last
	*last = cur
	return d
}

// snapshot is the rows, cumulative, and the histogram of the window since the
// last snapshot. haveTotals is false when io_totals could not be read: the
// window's histogram is then empty, and its calls land in the next one.
func (a *ioAgg) snapshot(t bpf.IOTotals, haveTotals bool) IOEBPFSnapshot {
	buckets := []LatencyBucket{
		{Label: "<0.1ms"},
		{Label: "0.1-1ms"},
		{Label: "1-5ms"},
		{Label: "5-20ms"},
		{Label: ">20ms"},
	}
	if haveTotals {
		for i := range buckets {
			buckets[i].Read = float64(grow(&a.hist[bpf.IOOpRead][i], t.Hist[bpf.IOOpRead][i]))
			buckets[i].Write = float64(grow(&a.hist[bpf.IOOpWrite][i], t.Hist[bpf.IOOpWrite][i]))
		}
		grow(&a.lost.LostReads, t.LostReads)
		grow(&a.lost.LostWrites, t.LostWrites)
		grow(&a.lost.LostBytes, t.LostBytes)
		grow(&a.lost.LostLatNs, t.LostLatNs)
	}

	files := make([]IOFileStats, 0, len(a.files)+1)
	for path, f := range a.files {
		files = append(files, IOFileStats{
			Path:      path,
			Type:      f.fileType,
			Reads:     f.reads,
			Writes:    f.writes,
			Bytes:     f.bytes,
			LatencyMs: meanMs(f.latSumNs, f.reads+f.writes),
		})
	}
	// The calls with no key: counted, and said to be unattributed, rather than
	// missing from every row while the histogram has them.
	if n := a.lost.LostReads + a.lost.LostWrites; n > 0 {
		files = append(files, IOFileStats{
			Path:      IOLostPath,
			Type:      "lost",
			Reads:     a.lost.LostReads,
			Writes:    a.lost.LostWrites,
			Bytes:     a.lost.LostBytes,
			LatencyMs: meanMs(a.lost.LostLatNs, n),
		})
	}
	return IOEBPFSnapshot{TopFiles: files, Buckets: buckets}
}

func meanMs(sumNs, n uint64) float64 {
	if n == 0 {
		return 0
	}
	return float64(sumNs) / float64(n) / 1e6
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
		return "file"
	}
}
