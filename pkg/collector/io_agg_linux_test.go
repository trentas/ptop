//go:build linux

package collector

import (
	"os"
	"testing"
	"time"

	"github.com/trentas/ptop/internal/bpf"
)

// The io probe counts in the kernel and the collector folds what it reads
// (#181). These pin the folding: no call counted twice, none lost, across a
// key's lives and the order its records and map reads arrive in.

const aggTGID = 7

func aggKey(fd uint32, ino uint64) bpf.IOKey { return bpf.IOKey{TGID: aggTGID, FD: fd, Ino: ino} }

// openAt names (fd, ino) by an absolute path, as an open record would: the fd
// is not open in this process, so the path as passed is the name.
func openAt(a *ioAgg, fd uint32, ino uint64, path string, now time.Time) {
	a.record(bpf.IORecord{Kind: bpf.IORecOpen, TGID: aggTGID, FD: fd, Ino: ino, Dfd: atFDCWD, Path: path}, now)
}

func row(t *testing.T, s IOEBPFSnapshot, path string) IOFileStats {
	t.Helper()
	for _, f := range s.TopFiles {
		if f.Path == path {
			return f
		}
	}
	t.Fatalf("no row %q in %+v", path, s.TopFiles)
	return IOFileStats{}
}

func TestIOAggOneLife(t *testing.T) {
	a := newIOAgg(os.Getpid())
	now := time.Now()
	k := aggKey(900, 1001)
	openAt(a, 900, 1001, "/data/a.log", now)
	a.record(bpf.IORecord{Kind: bpf.IORecSeen, TGID: aggTGID, FD: 900, Ino: 1001, Gen: 1}, now)

	a.read(map[bpf.IOKey]bpf.IOStat{k: {Gen: 1, Reads: 2, Writes: 3, Bytes: 100, LatNs: 5e6}}, now, true)
	a.read(map[bpf.IOKey]bpf.IOStat{k: {Gen: 1, Reads: 4, Writes: 3, Bytes: 140, LatNs: 7e6}}, now, true)
	a.record(bpf.IORecord{Kind: bpf.IORecClose, TGID: aggTGID, FD: 900, Ino: 1001, Gen: 1,
		Stat: bpf.IOStat{Gen: 1, Reads: 5, Writes: 5, Bytes: 200, LatNs: 10e6}}, now)
	// A read between the close record and the kernel's delete still shows the
	// closed life: it must not count again.
	a.read(map[bpf.IOKey]bpf.IOStat{k: {Gen: 1, Reads: 5, Writes: 5, Bytes: 200, LatNs: 10e6}}, now, true)

	r := row(t, a.snapshot(bpf.IOTotals{}, true), "/data/a.log")
	if r.Reads != 5 || r.Writes != 5 || r.Bytes != 200 || r.LatencyMs != 1 {
		t.Errorf("row %+v, want 5 reads, 5 writes, 200 bytes, 1ms mean", r)
	}
	if len(a.lives) != 0 {
		t.Errorf("a closed life is still tracked: %+v", a.lives)
	}
}

// A file closed and opened again on the same fd gets the same (fd, inode): the
// second life's counts add to the first's, never diffed against them.
func TestIOAggSecondLifeOfAKey(t *testing.T) {
	a := newIOAgg(os.Getpid())
	now := time.Now()
	k := aggKey(901, 1002)
	openAt(a, 901, 1002, "/data/b.db", now)
	a.read(map[bpf.IOKey]bpf.IOStat{k: {Gen: 1, Writes: 7}}, now, true)
	a.record(bpf.IORecord{Kind: bpf.IORecClose, TGID: aggTGID, FD: 901, Ino: 1002, Gen: 1,
		Stat: bpf.IOStat{Gen: 1, Writes: 7}}, now)

	openAt(a, 901, 1002, "/data/b.db", now)
	a.read(map[bpf.IOKey]bpf.IOStat{k: {Gen: 2, Writes: 3}}, now, true)

	if r := row(t, a.snapshot(bpf.IOTotals{}, true), "/data/b.db"); r.Writes != 10 {
		t.Errorf("writes %d, want 7 + 3", r.Writes)
	}
}

// The close record carries the life's final counts; a map read that saw less
// before it is topped up to them, not added to them.
func TestIOAggCloseAfterARead(t *testing.T) {
	a := newIOAgg(os.Getpid())
	now := time.Now()
	k := aggKey(902, 1003)
	openAt(a, 902, 1003, "/data/c", now)
	a.read(map[bpf.IOKey]bpf.IOStat{k: {Gen: 5, Reads: 4}}, now, true)
	a.record(bpf.IORecord{Kind: bpf.IORecClose, TGID: aggTGID, FD: 902, Ino: 1003, Gen: 5,
		Stat: bpf.IOStat{Gen: 5, Reads: 6}}, now)
	if r := row(t, a.snapshot(bpf.IOTotals{}, true), "/data/c"); r.Reads != 6 {
		t.Errorf("reads %d, want 6", r.Reads)
	}
}

// A read that caught one counter behind where an earlier read saw it moves
// nothing back.
func TestIOAggHighWater(t *testing.T) {
	a := newIOAgg(os.Getpid())
	now := time.Now()
	k := aggKey(903, 1004)
	openAt(a, 903, 1004, "/data/d", now)
	for _, r := range []uint64{5, 4, 6} {
		a.read(map[bpf.IOKey]bpf.IOStat{k: {Gen: 1, Reads: r}}, now, true)
	}
	if r := row(t, a.snapshot(bpf.IOTotals{}, true), "/data/d"); r.Reads != 6 {
		t.Errorf("reads %d, want 6", r.Reads)
	}
}

// The kernel's histogram is cumulative; each snapshot carries its window.
func TestIOAggHistogramPerWindow(t *testing.T) {
	a := newIOAgg(os.Getpid())
	var tot bpf.IOTotals
	tot.Hist[bpf.IOOpRead][3] = 3
	tot.Hist[bpf.IOOpWrite][0] = 10
	s := a.snapshot(tot, true)
	if s.Buckets[3].Read != 3 || s.Buckets[0].Write != 10 {
		t.Errorf("first window %+v", s.Buckets)
	}
	tot.Hist[bpf.IOOpRead][3] = 5
	s = a.snapshot(tot, true)
	if s.Buckets[3].Read != 2 || s.Buckets[0].Write != 0 {
		t.Errorf("second window %+v, want 2 reads in 5-20ms and no writes", s.Buckets)
	}
	// Totals unreadable for a window: it is empty, and the next one has its calls.
	s = a.snapshot(bpf.IOTotals{}, false)
	if s.Buckets[3].Read != 0 {
		t.Errorf("a window without totals %+v", s.Buckets)
	}
	tot.Hist[bpf.IOOpRead][3] = 6
	if s = a.snapshot(tot, true); s.Buckets[3].Read != 1 {
		t.Errorf("window after the gap %+v, want 1", s.Buckets)
	}
	if got := s.Buckets[3].Label; got != "5-20ms" {
		t.Errorf("bucket 3 is %q", got)
	}
}

// Calls the kernel had no key for are a row of their own, never missing.
func TestIOAggLostRow(t *testing.T) {
	a := newIOAgg(os.Getpid())
	s := a.snapshot(bpf.IOTotals{}, true)
	for _, f := range s.TopFiles {
		if f.Path == IOLostPath {
			t.Fatal("a lost row with nothing lost")
		}
	}
	s = a.snapshot(bpf.IOTotals{LostReads: 3, LostWrites: 1, LostBytes: 64, LostLatNs: 8e6}, true)
	r := row(t, s, IOLostPath)
	if r.Reads != 3 || r.Writes != 1 || r.Bytes != 64 || r.LatencyMs != 2 {
		t.Errorf("lost row %+v", r)
	}
}

// A key idle for ioIdleRetire is handed back for retirement, and what it held
// is added once.
func TestIOAggRetiresIdleKeys(t *testing.T) {
	a := newIOAgg(os.Getpid())
	t0 := time.Now()
	k := aggKey(904, 1005)
	openAt(a, 904, 1005, "/data/e", t0)
	if idle := a.read(map[bpf.IOKey]bpf.IOStat{k: {Gen: 1, Writes: 2}}, t0, true); len(idle) != 0 {
		t.Fatalf("a key that just moved is idle: %v", idle)
	}
	later := t0.Add(ioIdleRetire)
	idle := a.read(map[bpf.IOKey]bpf.IOStat{k: {Gen: 1, Writes: 2}}, later, true)
	if len(idle) != 1 || idle[0] != k {
		t.Fatalf("idle %v, want [%v]", idle, k)
	}
	a.retired(k, bpf.IOStat{Gen: 1, Writes: 3}, later) // one more write before the delete
	a.read(map[bpf.IOKey]bpf.IOStat{}, later, true)
	if r := row(t, a.snapshot(bpf.IOTotals{}, true), "/data/e"); r.Writes != 3 {
		t.Errorf("writes %d, want 3", r.Writes)
	}
}

// A life the map no longer shows, with no close record (lost to a full ring),
// is forgotten after two reads, so the state cannot grow without bound.
func TestIOAggForgetsVanishedLives(t *testing.T) {
	a := newIOAgg(os.Getpid())
	now := time.Now()
	k := aggKey(905, 1006)
	a.read(map[bpf.IOKey]bpf.IOStat{k: {Gen: 1, Reads: 1}}, now, true)
	a.read(map[bpf.IOKey]bpf.IOStat{}, now, true)
	if len(a.lives) != 1 {
		t.Fatalf("dropped after one read: %d lives", len(a.lives))
	}
	a.read(map[bpf.IOKey]bpf.IOStat{}, now, true)
	if len(a.lives) != 0 {
		t.Errorf("%d lives after two reads without it", len(a.lives))
	}
}

// A life seen on the ring after the map read that would have shown it is kept
// until a read has had the chance to.
func TestIOAggKeepsALifeSeenAfterTheRead(t *testing.T) {
	a := newIOAgg(os.Getpid())
	now := time.Now()
	a.read(map[bpf.IOKey]bpf.IOStat{}, now, true)
	a.record(bpf.IORecord{Kind: bpf.IORecSeen, TGID: aggTGID, FD: 906, Ino: 1007, Gen: 1}, now)
	a.read(map[bpf.IOKey]bpf.IOStat{}, now, true)
	if len(a.lives) != 1 {
		t.Errorf("a life seen after a read was dropped by the next one")
	}
}

// Cgroup mode names nothing: rows are "fd=N".
func TestIOAggCgroupModeRows(t *testing.T) {
	a := newIOAgg(0)
	now := time.Now()
	a.read(map[bpf.IOKey]bpf.IOStat{aggKey(3, 42): {Gen: 1, Writes: 1}}, now, true)
	if r := row(t, a.snapshot(bpf.IOTotals{}, true), "fd=3"); r.Writes != 1 {
		t.Errorf("row %+v", r)
	}
}

// A key the ring has not announced yet, read while the ring still held a
// backlog, waits for its records: its open may be among them, and named now
// from its fd's link it would read "fd=N" (#181).
func TestIOAggWaitsForTheRingBeforeNaming(t *testing.T) {
	a := newIOAgg(os.Getpid())
	now := time.Now()
	k := aggKey(907, 1008)
	a.read(map[bpf.IOKey]bpf.IOStat{k: {Gen: 1, Writes: 1}}, now, false)
	if len(a.lives) != 0 || len(a.files) != 0 {
		t.Fatalf("a key read before its records was named: %+v", a.files)
	}
	openAt(a, 907, 1008, "/data/f.log", now)
	a.record(bpf.IORecord{Kind: bpf.IORecSeen, TGID: aggTGID, FD: 907, Ino: 1008, Gen: 1}, now)
	a.record(bpf.IORecord{Kind: bpf.IORecClose, TGID: aggTGID, FD: 907, Ino: 1008, Gen: 1,
		Stat: bpf.IOStat{Gen: 1, Writes: 1}}, now)
	s := a.snapshot(bpf.IOTotals{}, true)
	if r := row(t, s, "/data/f.log"); r.Writes != 1 {
		t.Errorf("row %+v", r)
	}
	for _, f := range s.TopFiles {
		if f.Path == "fd=907" {
			t.Errorf("a row named by fd: %+v", f)
		}
	}
}
