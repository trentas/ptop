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

// IOEvent is the 1:1 layout of struct io_event in programs/io.bpf.c.
// Fixed size 32 bytes; binary.LittleEndian.Read parses it directly from the ring buffer.
type IOEvent struct {
	TsNs  uint64
	LatNs uint64
	Bytes uint64
	FD    uint32
	Op    uint32 // 0=read, 1=write
	TGID  uint32
	_     uint32 // pad
}

const (
	IOOpRead  uint32 = 0
	IOOpWrite uint32 = 1
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
	if len(rec.RawSample) < 32 {
		return ev, fmt.Errorf("short event: %d bytes", len(rec.RawSample))
	}
	if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
		return ev, fmt.Errorf("decode event: %w", err)
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
