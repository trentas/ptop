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

//go:embed programs/io.bpf.o
var ioBPFObj []byte

// IOEvent é o layout 1:1 da struct io_event em programs/io.bpf.c.
// Tamanho fixo 32 bytes; binary.LittleEndian.Read parseia direto da ring buffer.
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

// IOTracer carrega io.bpf.o, attacha tracepoints sys_enter/exit_read/write,
// abre ring buffer reader e expõe Next() pra entregar eventos parseados.
type IOTracer struct {
	coll  *ebpf.Collection
	links []link.Link
	rb    *ringbuf.Reader
}

func OpenIOTracer(pid int) (*IOTracer, error) {
	if pid <= 0 {
		return nil, errors.New("pid inválido")
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

	// Setar target_pid
	targetMap := coll.Maps["io_target_pid"]
	if targetMap == nil {
		t.Close()
		return nil, errors.New("io_target_pid map ausente")
	}
	var key uint32 = 0
	val := uint32(pid)
	if err := targetMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
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
			return nil, fmt.Errorf("program %s ausente", a.prog)
		}
		l, err := link.Tracepoint(a.group, a.name, prog, nil)
		if err != nil {
			t.Close()
			return nil, fmt.Errorf("attach %s/%s: %w", a.group, a.name, err)
		}
		t.links = append(t.links, l)
	}

	// Abre ring buffer reader. Reads bloqueiam até evento chegar ou Close.
	eventsMap := coll.Maps["io_events"]
	if eventsMap == nil {
		t.Close()
		return nil, errors.New("io_events ringbuf ausente")
	}
	rb, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}
	t.rb = rb

	return t, nil
}

// Next bloqueia até o próximo evento chegar do kernel. Retorna io.EOF se o
// tracer foi fechado. Erros transientes (sample lost, etc) são contornados.
func (t *IOTracer) Next() (IOEvent, error) {
	var ev IOEvent
	if t == nil || t.rb == nil {
		return ev, errors.New("tracer não inicializado")
	}
	rec, err := t.rb.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return ev, io.EOF
		}
		return ev, err
	}
	if len(rec.RawSample) < 32 {
		return ev, fmt.Errorf("evento curto: %d bytes", len(rec.RawSample))
	}
	if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
		return ev, fmt.Errorf("decode event: %w", err)
	}
	return ev, nil
}

func (t *IOTracer) Close() error {
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
