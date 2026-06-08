//go:build linux && ebpf

package bpf

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed programs/proc.bpf.o
var procBPFObj []byte

// procRecordSize is the on-wire size of struct proc_event in programs/proc.bpf.c
// (#60). The trailing _pad makes this match C's sizeof exactly (168 bytes).
const procRecordSize = 168

// ProcRecord is the 1:1 layout of struct proc_event. binary.LittleEndian parses
// it directly from the ring buffer. Pad mirrors the C struct's alignment slot.
type ProcRecord struct {
	TsNs     uint64
	Kind     uint32
	PID      int32
	PPID     int32
	Pad      uint32
	Comm     [16]byte
	Filename [128]byte
}

// ProcTracer loads proc.bpf.o, seeds the tracked-pid set with the target's
// global pid, attaches the sched fork/exec/exit tracepoints, and exposes Next()
// to deliver parsed lifecycle records.
type ProcTracer struct {
	coll  *ebpf.Collection
	links []link.Link
	rb    *ringbuf.Reader
}

func OpenProcTracer(pid int) (*ProcTracer, error) {
	if pid <= 0 {
		return nil, errors.New("invalid pid")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(procBPFObj))
	if err != nil {
		return nil, fmt.Errorf("parse proc BPF object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load proc collection: %w", err)
	}
	t := &ProcTracer{coll: coll}

	// Seed the tracked set with the target's global (init-ns) pid — the
	// subtree grows from here on each observed fork.
	trackedMap := coll.Maps["proc_tracked"]
	if trackedMap == nil {
		t.Close()
		return nil, errors.New("proc_tracked map missing")
	}
	gpid := uint32(globalPID(pid))
	var present uint8 = 1
	if err := trackedMap.Update(&gpid, &present, ebpf.UpdateAny); err != nil {
		t.Close()
		return nil, fmt.Errorf("seed proc_tracked: %w", err)
	}

	// Attach the three sched tracepoints. They are universally present, but we
	// attach tolerantly and only fail if NONE attached — so a kernel missing
	// one still yields partial lineage rather than nothing.
	attach := func(name, prog string) {
		p := coll.Programs[prog]
		if p == nil {
			return
		}
		if l, err := link.Tracepoint("sched", name, p, nil); err == nil {
			t.links = append(t.links, l)
		}
	}
	attach("sched_process_fork", "handle_fork")
	attach("sched_process_exec", "handle_exec")
	attach("sched_process_exit", "handle_exit")
	if len(t.links) == 0 {
		t.Close()
		return nil, errors.New("attach sched process tracepoints: none attached")
	}

	evMap := coll.Maps["proc_events"]
	if evMap == nil {
		t.Close()
		return nil, errors.New("proc_events ringbuf missing")
	}
	rb, err := ringbuf.NewReader(evMap)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("proc ringbuf reader: %w", err)
	}
	t.rb = rb

	return t, nil
}

// Next blocks until the next lifecycle record arrives. Returns io.EOF once the
// tracer is closed. A short/garbled record is reported as an error but does not
// close the stream — the caller keeps reading.
func (t *ProcTracer) Next() (ProcRecord, error) {
	var rec ProcRecord
	if t == nil || t.rb == nil {
		return rec, errors.New("tracer not initialized")
	}
	r, err := t.rb.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return rec, io.EOF
		}
		return rec, err
	}
	if len(r.RawSample) < procRecordSize {
		return rec, fmt.Errorf("short proc event: %d bytes", len(r.RawSample))
	}
	if err := binary.Read(bytes.NewReader(r.RawSample), binary.LittleEndian, &rec); err != nil {
		return rec, fmt.Errorf("decode proc event: %w", err)
	}
	return rec, nil
}

func (t *ProcTracer) Close() error {
	if t == nil {
		return nil
	}
	if t.rb != nil {
		_ = t.rb.Close()
		t.rb = nil
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
