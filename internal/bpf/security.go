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

//go:embed programs/security.bpf.o
var securityBPFObj []byte

// secStackDepth mirrors SEC_STACK_DEPTH in programs/security.bpf.c.
const secStackDepth = 32

// secRecordSize is the on-wire size of struct sec_event (56 bytes — a multiple
// of 8, so this matches C's sizeof and the Go packed layout).
const secRecordSize = 56

// SecurityRecord is the 1:1 layout of struct sec_event in
// programs/security.bpf.c. binary.LittleEndian parses it from the ring buffer.
type SecurityRecord struct {
	TsNs         uint64
	Addr         uint64
	Len          uint64
	Kind         uint32
	Op           uint32
	Prot         uint32
	Flags        uint32
	LsmRequested uint32
	LsmDenied    uint32
	LsmAudited   uint32
	StackID      int32
}

// SecurityTracer loads security.bpf.o, attaches the mmap/mprotect (PROT_EXEC)
// and SELinux AVC tracepoints filtered to the target, and exposes Next() +
// ResolveStack() for the exec-map call site.
type SecurityTracer struct {
	coll      *ebpf.Collection
	links     []link.Link
	rb        *ringbuf.Reader
	stacksMap *ebpf.Map
}

func OpenSecurityTracer(pid int) (*SecurityTracer, error) {
	if pid <= 0 {
		return nil, errors.New("invalid pid")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(securityBPFObj))
	if err != nil {
		return nil, fmt.Errorf("parse security BPF object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load security collection: %w", err)
	}
	t := &SecurityTracer{coll: coll}

	tfMap := coll.Maps["sec_target_pid"]
	if tfMap == nil {
		t.Close()
		return nil, errors.New("sec_target_pid map missing")
	}
	tf, err := resolveTarget(pid)
	if err != nil {
		t.Close()
		return nil, err
	}
	if err := writeTargetFilter(tfMap, tf); err != nil {
		t.Close()
		return nil, fmt.Errorf("set sec_target_pid: %w", err)
	}

	// exec-map probes are the core; attach both, fail only if NEITHER attaches.
	attach := func(group, name, prog string) bool {
		p := coll.Programs[prog]
		if p == nil {
			return false
		}
		l, err := link.Tracepoint(group, name, p, nil)
		if err != nil {
			return false
		}
		t.links = append(t.links, l)
		return true
	}
	okMmap := attach("syscalls", "sys_enter_mmap", "tp_sys_enter_mmap")
	okMprot := attach("syscalls", "sys_enter_mprotect", "tp_sys_enter_mprotect")
	if !okMmap && !okMprot {
		t.Close()
		return nil, errors.New("attach mmap/mprotect tracepoints: neither attached")
	}
	// LSM (SELinux AVC) is best-effort: absent on non-SELinux kernels.
	attach("avc", "selinux_audited", "tp_selinux_audited")

	t.stacksMap = coll.Maps["sec_stacks"]
	if t.stacksMap == nil {
		t.Close()
		return nil, errors.New("sec_stacks map missing")
	}

	evMap := coll.Maps["sec_events"]
	if evMap == nil {
		t.Close()
		return nil, errors.New("sec_events ringbuf missing")
	}
	rb, err := ringbuf.NewReader(evMap)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("security ringbuf reader: %w", err)
	}
	t.rb = rb

	return t, nil
}

// Next blocks until the next security record arrives. Returns io.EOF once the
// tracer is closed. A short/garbled record is reported as an error but keeps
// the stream open.
func (t *SecurityTracer) Next() (SecurityRecord, error) {
	var rec SecurityRecord
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
	if len(r.RawSample) < secRecordSize {
		return rec, fmt.Errorf("short security event: %d bytes", len(r.RawSample))
	}
	if err := binary.Read(bytes.NewReader(r.RawSample), binary.LittleEndian, &rec); err != nil {
		return rec, fmt.Errorf("decode security event: %w", err)
	}
	return rec, nil
}

// ResolveStack returns the user-stack frames captured for stackID (leaf first),
// trailing zero slots trimmed. A negative id (capture failed / LSM event) yields
// nil. Mirrors HeapTracer.ResolveStack.
func (t *SecurityTracer) ResolveStack(stackID int32) ([]uint64, error) {
	if stackID < 0 {
		return nil, nil
	}
	if t == nil || t.stacksMap == nil {
		return nil, errors.New("tracer not initialized")
	}
	var frames [secStackDepth]uint64
	if err := t.stacksMap.Lookup(uint32(stackID), &frames); err != nil {
		return nil, err
	}
	n := len(frames)
	for n > 0 && frames[n-1] == 0 {
		n--
	}
	return frames[:n], nil
}

func (t *SecurityTracer) Close() error {
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
