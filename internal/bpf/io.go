//go:build linux && ebpf

package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// IORecord is one record of the io_events ring (#162, #181): an open naming
// the fd it returned, a key's first read or write, or a key's final counts when
// the target closed its fd. The reads and writes themselves are counted in the
// kernel (Stats, Totals), not sent one by one. The header is struct io_record
// in programs/io.bpf.c, ioRecordSize bytes.
type IORecord struct {
	Kind uint32 // IORecOpen, IORecSeen, IORecClose
	TGID uint32
	FD   uint32
	// Dfd and Path are an open's: the path as the program passed it, and the
	// directory fd it is relative to (unix.AT_FDCWD for the working directory).
	Dfd int32
	// Ino is the inode number of the file behind FD — what
	// /proc/<pid>/fdinfo/<fd> prints as `ino:`. 0 when the fd table could not
	// be read.
	Ino  uint64
	Gen  uint64 // IORecSeen, IORecClose: the key's IOStat.Gen
	Path string // IORecOpen
	Stat IOStat // IORecClose: the key's counts when its fd was closed
}

// Key is the io_stats key the record is about.
func (r IORecord) Key() IOKey { return IOKey{TGID: r.TGID, FD: r.FD, Ino: r.Ino} }

const (
	IORecOpen  uint32 = 0
	IORecSeen  uint32 = 1
	IORecClose uint32 = 2
)

// IOKey is struct io_key: the file a call hit.
type IOKey struct {
	TGID uint32
	FD   uint32
	Ino  uint64
}

// IOStat is struct io_stat: one key's counts since the kernel created it.
// Gen, when it was created, tells one life of a key from the next: a key is
// deleted when the target closes its fd and created again by the next call on
// the same (fd, inode).
type IOStat struct {
	Gen    uint64
	Reads  uint64
	Writes uint64
	Bytes  uint64
	LatNs  uint64 // summed over Reads + Writes
}

// IOStatsMax is io_stats' size (IO_STATS_MAX in programs/io.bpf.c): how many
// files the target can hold open with I/O on them before further calls are
// counted as lost. OpenIOTracer checks the object against it.
const IOStatsMax = 16384

// IOBuckets is the latency histogram's size: <0.1ms, <1ms, <5ms, <20ms, the
// rest. IOOpRead and IOOpWrite index its first dimension.
const IOBuckets = 5

const (
	IOOpRead  = 0
	IOOpWrite = 1
)

// IOTotals is struct io_totals summed over the CPUs: cumulative since the probe
// loaded.
type IOTotals struct {
	Hist [2][IOBuckets]uint64
	// Calls io_stats had no room for: in Hist, and in no key.
	LostReads  uint64
	LostWrites uint64
	LostBytes  uint64
	LostLatNs  uint64
}

// ioRecordSize is sizeof(struct io_record); an open carries ioPathMax more
// bytes, a close an io_stat (ioStatSize).
const (
	ioRecordSize = 32
	ioPathMax    = 256
	ioStatSize   = 40
)

// FSEventRecord is the 1:1 layout of struct fs_event in programs/io.bpf.c (#57).
// Fixed size 536 bytes; binary.LittleEndian parses it directly from the fs_events
// ring buffer. Path/NewPath are NUL-terminated C strings in fixed buffers
// (decoded + trimmed on the collector side).
type FSEventRecord struct {
	TsNs    uint64
	TGID    uint32
	Ret     int32 // syscall return: negative errno on failure, >=0 on success
	Op      uint32
	_       uint32 // pad
	Path    [256]byte
	NewPath [256]byte
}

// FS op codes — must match FS_OP_* in programs/io.bpf.c.
const (
	FSOpOpenDenied uint32 = 0
	FSOpUnlink     uint32 = 1
	FSOpRename     uint32 = 2
)

// IOTracer loads io.bpf.o and attaches it to raw_syscalls (#159). Reads and
// writes are counted in the kernel and read with Stats and Totals (#181); Next
// delivers the records that name files (#162), NextFSEvent the fs events (#57).
type IOTracer struct {
	coll   *ebpf.Collection
	links  []link.Link
	rb     *ringbuf.Reader
	fsrb   *ringbuf.Reader // #57 — fs_events channel
	stats  *ebpf.Map       // io_stats (#181)
	totals *ebpf.Map       // io_totals (#181)
}

func OpenIOTracer(target Target) (*IOTracer, error) {
	if err := target.validate(); err != nil {
		return nil, err
	}
	if !target.IsCgroup() {
		if err := refuseCompatTarget(target.PID); err != nil {
			return nil, err
		}
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ioBPFObj))
	if err != nil {
		return nil, fmt.Errorf("parse io BPF object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load io collection: %w", err)
	}
	t := &IOTracer{coll: coll}

	// Set the target filter
	targetMap := coll.Maps["io_target_pid"]
	if targetMap == nil {
		t.Close()
		return nil, errors.New("io_target_pid map missing")
	}
	tf, err := resolveTarget(target)
	if err != nil {
		t.Close()
		return nil, err
	}
	if err := writeTargetFilter(targetMap, tf); err != nil {
		t.Close()
		return nil, fmt.Errorf("set io_target_pid: %w", err)
	}

	// One raw_syscalls pair serves read/write and the fs-semantics calls alike
	// (#159). The per-syscall events this replaced copy user memory into the
	// event on kernel 7.0 for write, openat, unlinkat and renameat*, and the
	// program never ran for those calls made on any CPU but the first — the
	// selftest's io case plants them on every CPU to keep it that way.
	for _, a := range []struct{ name, prog string }{
		{"sys_enter", "handle_sys_enter"},
		{"sys_exit", "handle_sys_exit"},
	} {
		prog := coll.Programs[a.prog]
		if prog == nil {
			t.Close()
			return nil, fmt.Errorf("program %s missing", a.prog)
		}
		l, err := link.Tracepoint("raw_syscalls", a.name, prog, nil)
		if err != nil {
			t.Close()
			return nil, fmt.Errorf("attach raw_syscalls/%s: %w", a.name, err)
		}
		t.links = append(t.links, l)
	}

	t.stats, t.totals = coll.Maps["io_stats"], coll.Maps["io_totals"]
	if t.stats == nil || t.totals == nil {
		t.Close()
		return nil, errors.New("io_stats or io_totals map missing")
	}
	if n := t.stats.MaxEntries(); n != IOStatsMax {
		t.Close()
		return nil, fmt.Errorf("io_stats holds %d keys, IOStatsMax says %d: the object and the loader disagree", n, IOStatsMax)
	}

	// Open ring buffer reader. Reads block until an event arrives or Close.
	eventsMap := coll.Maps["io_events"]
	if eventsMap == nil {
		t.Close()
		return nil, errors.New("io_events ringbuf missing")
	}
	rb, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}
	t.rb = rb

	// fs_events ring buffer (#57). Part of our own program — a miss means a
	// corrupt object, so it's fatal (matching io_events above).
	fsMap := coll.Maps["fs_events"]
	if fsMap == nil {
		t.Close()
		return nil, errors.New("fs_events ringbuf missing")
	}
	fsrb, err := ringbuf.NewReader(fsMap)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("fs ringbuf reader: %w", err)
	}
	t.fsrb = fsrb

	return t, nil
}

// Next blocks until the next record arrives from the kernel, or the deadline
// set by SetDeadline passes (an error wrapping os.ErrDeadlineExceeded).
// Returns io.EOF once the tracer is interrupted or closed.
func (t *IOTracer) Next() (IORecord, error) {
	var r IORecord
	if t == nil || t.rb == nil {
		return r, errors.New("tracer not initialized")
	}
	rec, err := t.rb.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return r, io.EOF
		}
		return r, err
	}
	return decodeIORecord(rec.RawSample)
}

// SetDeadline bounds how long Next blocks; the zero time removes the bound.
// Call it from the goroutine that calls Next: the reader holds its lock while
// it waits.
func (t *IOTracer) SetDeadline(d time.Time) {
	if t != nil && t.rb != nil {
		t.rb.SetDeadline(d)
	}
}

// decodeIORecord parses one io_events record.
func decodeIORecord(raw []byte) (IORecord, error) {
	var r IORecord
	if len(raw) < ioRecordSize {
		return r, fmt.Errorf("short io record: %d bytes", len(raw))
	}
	le := binary.LittleEndian
	r.Kind = le.Uint32(raw[0:])
	r.TGID = le.Uint32(raw[4:])
	r.FD = le.Uint32(raw[8:])
	r.Dfd = int32(le.Uint32(raw[12:]))
	r.Ino = le.Uint64(raw[16:])
	r.Gen = le.Uint64(raw[24:])
	body := raw[ioRecordSize:]
	switch r.Kind {
	case IORecOpen:
		if len(body) < ioPathMax {
			return r, fmt.Errorf("short open record: %d bytes", len(raw))
		}
		path := body[:ioPathMax]
		if i := bytes.IndexByte(path, 0); i >= 0 {
			path = path[:i]
		}
		r.Path = string(path)
	case IORecClose:
		if len(body) < ioStatSize {
			return r, fmt.Errorf("short close record: %d bytes", len(raw))
		}
		r.Stat = IOStat{
			Gen:    le.Uint64(body[0:]),
			Reads:  le.Uint64(body[8:]),
			Writes: le.Uint64(body[16:]),
			Bytes:  le.Uint64(body[24:]),
			LatNs:  le.Uint64(body[32:]),
		}
	case IORecSeen:
	default:
		return r, fmt.Errorf("unknown io record kind %d", r.Kind)
	}
	return r, nil
}

// Stats reads every key of io_stats. Each counter is read whole, but a key is
// not read in one step, so one counter can be a call ahead of another: each
// is monotonic within a key's life, and the collector keeps a high-water mark.
func (t *IOTracer) Stats() (map[IOKey]IOStat, error) {
	if t == nil || t.stats == nil {
		return nil, errors.New("tracer not initialized")
	}
	out := make(map[IOKey]IOStat)
	var k IOKey
	var v IOStat
	iter := t.stats.Iterate()
	for iter.Next(&k, &v) {
		out[k] = v
	}
	return out, iter.Err()
}

// Totals sums io_totals over the CPUs.
func (t *IOTracer) Totals() (IOTotals, error) {
	var sum IOTotals
	if t == nil || t.totals == nil {
		return sum, errors.New("tracer not initialized")
	}
	var perCPU []IOTotals
	if err := t.totals.Lookup(uint32(0), &perCPU); err != nil {
		return sum, err
	}
	for _, c := range perCPU {
		for op := range c.Hist {
			for b := range c.Hist[op] {
				sum.Hist[op][b] += c.Hist[op][b]
			}
		}
		sum.LostReads += c.LostReads
		sum.LostWrites += c.LostWrites
		sum.LostBytes += c.LostBytes
		sum.LostLatNs += c.LostLatNs
	}
	return sum, nil
}

// RetireStat deletes k from io_stats and returns what it held, in one step
// where the kernel can (5.14+). ok is false when k was not there.
//
// A program that looked the entry up just before the delete adds its call to
// an entry no longer in the map, and that call is lost. The collector retires
// only keys idle for a long time, which is what keeps that window empty.
func (t *IOTracer) RetireStat(k IOKey) (IOStat, bool, error) {
	var v IOStat
	if t == nil || t.stats == nil {
		return v, false, errors.New("tracer not initialized")
	}
	err := t.stats.LookupAndDelete(&k, &v)
	if err == nil {
		return v, true, nil
	}
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return v, false, nil
	}
	// Before 5.14 a hash map has no lookup-and-delete: read it, then delete it.
	if err := t.stats.Lookup(&k, &v); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return v, false, nil
		}
		return v, false, err
	}
	if err := t.stats.Delete(&k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return v, false, err
	}
	return v, true, nil
}

// NextFSEvent blocks until the next fs-semantics event (#57) arrives from the
// kernel. Returns io.EOF once the tracer is closed. A short/garbled record is
// reported as an error but does not close the stream — the caller keeps reading.
func (t *IOTracer) NextFSEvent() (FSEventRecord, error) {
	var rec FSEventRecord
	if t == nil || t.fsrb == nil {
		return rec, errors.New("tracer not initialized")
	}
	r, err := t.fsrb.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return rec, io.EOF
		}
		return rec, err
	}
	if len(r.RawSample) < 536 {
		return rec, fmt.Errorf("short fs event: %d bytes", len(r.RawSample))
	}
	if err := binary.Read(bytes.NewReader(r.RawSample), binary.LittleEndian, &rec); err != nil {
		return rec, fmt.Errorf("decode fs event: %w", err)
	}
	return rec, nil
}

// Interrupt closes the ring readers, so a blocked Next or NextFSEvent returns
// io.EOF, and leaves the maps open for a reader to finish with. Safe to call
// while another goroutine reads; Close must wait until the readers are done.
func (t *IOTracer) Interrupt() {
	if t == nil {
		return
	}
	if t.rb != nil {
		_ = t.rb.Close()
	}
	if t.fsrb != nil {
		_ = t.fsrb.Close()
	}
}

func (t *IOTracer) Close() error {
	if t == nil {
		return nil
	}
	// Close the readers first so blocked Next/NextFSEvent unblock with io.EOF.
	t.Interrupt()
	t.rb, t.fsrb = nil, nil
	t.stats, t.totals = nil, nil
	for _, l := range t.links {
		_ = l.Close()
	}
	t.links = nil
	if t.coll != nil {
		t.coll.Close()
		t.coll = nil
	}
	return nil
}

// refuseCompatTarget fails for a 32-bit process; see compatExecutable for why.
// Pid mode only: a cgroup subtree has no single executable to read, so a 32-bit
// process inside one is not caught (documented in CLAUDE.md).
func refuseCompatTarget(pid int) error {
	if compatExecutable(fmt.Sprintf("/proc/%d/exe", pid)) {
		return fmt.Errorf("pid %d is a 32-bit process: the io probe matches syscalls by the 64-bit table's numbers and would misread its calls", pid)
	}
	return nil
}
