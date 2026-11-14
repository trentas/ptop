//go:build linux && ebpf

package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// IOEvent is one record of the io_events ring: a read or a write, or (#162) a
// successful open naming the fd it returned. The header is struct io_event in
// programs/io.bpf.c, ioEventSize bytes; an open is struct io_open_event, the
// header followed by the path.
type IOEvent struct {
	TsNs  uint64
	LatNs uint64
	Bytes uint64
	// Ino is the inode number of the file behind FD when the call entered (for
	// an open, when it returned) — what /proc/<pid>/fdinfo/<fd> prints as
	// `ino:`. 0 when the fd table could not be read.
	Ino  uint64
	FD   uint32
	Op   uint32 // IOOpRead, IOOpWrite, IOOpOpen
	TGID uint32
	// Dfd and Path are an open's: the path as the program passed it, and the
	// directory fd it is relative to (unix.AT_FDCWD for the working directory).
	Dfd  int32
	Path string
}

const (
	IOOpRead  uint32 = 0
	IOOpWrite uint32 = 1
	IOOpOpen  uint32 = 2
)

// ioEventSize is sizeof(struct io_event); an open carries ioPathMax more bytes.
const (
	ioEventSize = 48
	ioPathMax   = 256
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

// IOTracer loads io.bpf.o, attaches the read/write tracepoints (throughput) and
// the fs-semantics tracepoints (#57), and opens two ring buffer readers: Next()
// delivers throughput events, NextFSEvent() delivers fs events.
type IOTracer struct {
	coll  *ebpf.Collection
	links []link.Link
	rb    *ringbuf.Reader
	fsrb  *ringbuf.Reader // #57 — fs_events channel
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

// Next blocks until the next event arrives from the kernel. Returns io.EOF
// if the tracer was closed. Transient errors (sample lost, etc.) are skipped.
func (t *IOTracer) Next() (IOEvent, error) {
	var ev IOEvent
	if t == nil || t.rb == nil {
		return ev, errors.New("tracer not initialized")
	}
	rec, err := t.rb.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return ev, io.EOF
		}
		return ev, err
	}
	return decodeIOEvent(rec.RawSample)
}

// decodeIOEvent parses one io_events record.
func decodeIOEvent(raw []byte) (IOEvent, error) {
	var ev IOEvent
	if len(raw) < ioEventSize {
		return ev, fmt.Errorf("short event: %d bytes", len(raw))
	}
	le := binary.LittleEndian
	ev.TsNs = le.Uint64(raw[0:])
	ev.LatNs = le.Uint64(raw[8:])
	ev.Bytes = le.Uint64(raw[16:])
	ev.Ino = le.Uint64(raw[24:])
	ev.FD = le.Uint32(raw[32:])
	ev.Op = le.Uint32(raw[36:])
	ev.TGID = le.Uint32(raw[40:])
	ev.Dfd = int32(le.Uint32(raw[44:]))
	if ev.Op == IOOpOpen {
		if len(raw) < ioEventSize+ioPathMax {
			return ev, fmt.Errorf("short open event: %d bytes", len(raw))
		}
		path := raw[ioEventSize : ioEventSize+ioPathMax]
		if i := bytes.IndexByte(path, 0); i >= 0 {
			path = path[:i]
		}
		ev.Path = string(path)
	}
	return ev, nil
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

func (t *IOTracer) Close() error {
	if t == nil {
		return nil
	}
	// Close the readers first so blocked Next/NextFSEvent unblock with io.EOF.
	if t.rb != nil {
		_ = t.rb.Close()
		t.rb = nil
	}
	if t.fsrb != nil {
		_ = t.fsrb.Close()
		t.fsrb = nil
	}
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
