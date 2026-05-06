//go:build linux && ebpf

package bpf

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed programs/futex.bpf.o
var futexBPFObj []byte

// FutexStat espelha 1:1 `struct futex_stat` em programs/futex.bpf.c.
// 40 bytes (4 × u64 + 2 × u32).
type FutexStat struct {
	WaitCount   uint64
	WakeCount   uint64
	LatSumNs    uint64
	LatCount    uint64
	LastWaitTID uint32
	LastWakeTID uint32
}

// FutexTracer carrega futex.bpf.o, attacha sys_enter/exit_futex e expõe
// Stats() pra ler o map futex_stats keyed por uaddr.
type FutexTracer struct {
	coll  *ebpf.Collection
	links []link.Link
	smap  *ebpf.Map
}

func OpenFutexTracer(pid int) (*FutexTracer, error) {
	if pid <= 0 {
		return nil, errors.New("pid inválido")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(futexBPFObj))
	if err != nil {
		return nil, fmt.Errorf("parse futex BPF object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load futex collection: %w", err)
	}
	t := &FutexTracer{coll: coll}

	targetMap := coll.Maps["futex_target_pid"]
	if targetMap == nil {
		t.Close()
		return nil, errors.New("futex_target_pid map ausente")
	}
	var key uint32 = 0
	val := uint32(pid)
	if err := targetMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
		t.Close()
		return nil, fmt.Errorf("set futex_target_pid: %w", err)
	}

	t.smap = coll.Maps["futex_stats"]
	if t.smap == nil {
		t.Close()
		return nil, errors.New("futex_stats map ausente")
	}

	tracepoints := []struct{ group, name, prog string }{
		{"syscalls", "sys_enter_futex", "handle_enter_futex"},
		{"syscalls", "sys_exit_futex", "handle_exit_futex"},
	}
	for _, tp := range tracepoints {
		p := coll.Programs[tp.prog]
		if p == nil {
			t.Close()
			return nil, fmt.Errorf("program %s ausente", tp.prog)
		}
		l, err := link.Tracepoint(tp.group, tp.name, p, nil)
		if err != nil {
			t.Close()
			return nil, fmt.Errorf("attach %s/%s: %w", tp.group, tp.name, err)
		}
		t.links = append(t.links, l)
	}

	return t, nil
}

// Stats devolve um snapshot completo do map futex_stats: uaddr → stat.
func (t *FutexTracer) Stats() (map[uint64]FutexStat, error) {
	if t == nil || t.smap == nil {
		return nil, errors.New("tracer não inicializado")
	}
	out := make(map[uint64]FutexStat, 64)
	var k uint64
	var v FutexStat
	iter := t.smap.Iterate()
	for iter.Next(&k, &v) {
		out[k] = v
	}
	if err := iter.Err(); err != nil {
		return out, err
	}
	return out, nil
}

func (t *FutexTracer) Close() error {
	if t == nil {
		return nil
	}
	for _, l := range t.links {
		_ = l.Close()
	}
	t.links = nil
	if t.coll != nil {
		t.coll.Close()
		t.coll = nil
		t.smap = nil
	}
	return nil
}
