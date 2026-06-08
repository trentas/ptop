//go:build linux && ebpf

package bpf

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed programs/io.bpf.o
var ioBPFObj []byte

// IOEvent is the 1:1 layout of struct io_event in programs/io.bpf.c.
// Fixed size 32 bytes; binary.LittleEndian.Read parses it directly from the ring buffer.
type IOEvent struct {
	TsNs   uint64
	LatNs  uint64
	Bytes  uint64
	FD     uint32
	Op     uint32 // 0=read, 1=write
	TGID   uint32
	_      uint32 // pad
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

func OpenIOTracer(pid int) (*IOTracer, error) {
	if pid <= 0 {
		return nil, errors.New("invalid pid")
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
	tf, err := resolveTarget(pid)
	if err != nil {
		t.Close()
		return nil, err
	}
	if err := writeTargetFilter(targetMap, tf); err != nil {
		t.Close()
		return nil, fmt.Errorf("set io_target_pid: %w", err)
	}

	// Attach 4 tracepoints (enter/exit × read/write)
	attachments := []struct {
		group, name, prog string
	}{
		{"syscalls", "sys_enter_read", "handle_enter_read"},
		{"syscalls", "sys_exit_read", "handle_exit_read"},
		{"syscalls", "sys_enter_write", "handle_enter_write"},
		{"syscalls", "sys_exit_write", "handle_exit_write"},
	}
	for _, a := range attachments {
		prog := coll.Programs[a.prog]
		if prog == nil {
			t.Close()
			return nil, fmt.Errorf("program %s missing", a.prog)
		}
		l, err := link.Tracepoint(a.group, a.name, prog, nil)
		if err != nil {
			t.Close()
			return nil, fmt.Errorf("attach %s/%s: %w", a.group, a.name, err)
		}
		t.links = append(t.links, l)
	}

	// fs-semantics tracepoints (#57). Attached NON-fatally: the legacy
	// open/unlink/rename/renameat tracepoints don't exist on arm64 (only the
	// *at variants do), and a kernel could lack one — losing it just narrows fs
	// capture, it must not kill the throughput tracer. The *at variants exist on
	// every supported arch and cover all libc-routed filesystem calls.
	fsAttachments := []struct {
		group, name, prog string
	}{
		{"syscalls", "sys_enter_openat", "handle_enter_openat"},
		{"syscalls", "sys_exit_openat", "handle_exit_openat"},
		{"syscalls", "sys_enter_open", "handle_enter_open"},
		{"syscalls", "sys_exit_open", "handle_exit_open"},
		{"syscalls", "sys_enter_unlinkat", "handle_enter_unlinkat"},
		{"syscalls", "sys_exit_unlinkat", "handle_exit_unlinkat"},
		{"syscalls", "sys_enter_unlink", "handle_enter_unlink"},
		{"syscalls", "sys_exit_unlink", "handle_exit_unlink"},
		{"syscalls", "sys_enter_renameat2", "handle_enter_renameat2"},
		{"syscalls", "sys_exit_renameat2", "handle_exit_renameat2"},
		{"syscalls", "sys_enter_renameat", "handle_enter_renameat"},
		{"syscalls", "sys_exit_renameat", "handle_exit_renameat"},
		{"syscalls", "sys_enter_rename", "handle_enter_rename"},
		{"syscalls", "sys_exit_rename", "handle_exit_rename"},
	}
	for _, a := range fsAttachments {
		prog := coll.Programs[a.prog]
		if prog == nil {
			fmt.Fprintf(os.Stderr, "io: program %s missing; fs semantics degraded\n", a.prog)
			continue
		}
		l, err := link.Tracepoint(a.group, a.name, prog, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "io: attach %s/%s failed (%v); fs semantics degraded\n", a.group, a.name, err)
			continue
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
