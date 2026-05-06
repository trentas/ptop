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

//go:embed programs/memory.bpf.o
var memoryBPFObj []byte

// MemCounters espelha 1:1 `struct mem_counters` em programs/memory.bpf.c.
// 32 bytes (4 × u64).
type MemCounters struct {
	PageFaults  uint64
	MmapCount   uint64
	MunmapCount uint64
	BrkCount    uint64
}

// MemoryTracer carrega memory.bpf.o, attacha kprobe handle_mm_fault +
// tracepoints sys_enter_{mmap,munmap,brk}, expõe Stats() pra ler counters.
type MemoryTracer struct {
	coll  *ebpf.Collection
	links []link.Link
	cmap  *ebpf.Map
}

func OpenMemoryTracer(pid int) (*MemoryTracer, error) {
	if pid <= 0 {
		return nil, errors.New("pid inválido")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(memoryBPFObj))
	if err != nil {
		return nil, fmt.Errorf("parse memory BPF object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load memory collection: %w", err)
	}
	t := &MemoryTracer{coll: coll}

	targetMap := coll.Maps["mem_target_pid"]
	if targetMap == nil {
		t.Close()
		return nil, errors.New("mem_target_pid map ausente")
	}
	var key uint32 = 0
	val := uint32(pid)
	if err := targetMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
		t.Close()
		return nil, fmt.Errorf("set mem_target_pid: %w", err)
	}

	t.cmap = coll.Maps["mem_counters"]
	if t.cmap == nil {
		t.Close()
		return nil, errors.New("mem_counters map ausente")
	}

	// kprobe: pode falhar em kernels esquisitos (handle_mm_fault inlined ou
	// renomeado). Logamos warning e seguimos sem fault tracking — allocs
	// continuam funcionando via syscall tracepoints.
	if prog := coll.Programs["kp_handle_mm_fault"]; prog != nil {
		if l, err := link.Kprobe("handle_mm_fault", prog, nil); err == nil {
			t.links = append(t.links, l)
		} else {
			fmt.Printf("aviso: kprobe handle_mm_fault falhou: %v (page faults via /proc fallback)\n", err)
		}
	}

	// Syscall tracepoints — devem sempre funcionar em Linux >= 4.x.
	tracepoints := []struct{ group, name, prog string }{
		{"syscalls", "sys_enter_mmap", "tp_sys_enter_mmap"},
		{"syscalls", "sys_enter_munmap", "tp_sys_enter_munmap"},
		{"syscalls", "sys_enter_brk", "tp_sys_enter_brk"},
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

// Stats lê o slot 0 do mem_counters ARRAY (sempre presente).
func (t *MemoryTracer) Stats() (MemCounters, error) {
	if t == nil || t.cmap == nil {
		return MemCounters{}, errors.New("tracer não inicializado")
	}
	var key uint32 = 0
	var c MemCounters
	if err := t.cmap.Lookup(&key, &c); err != nil {
		return MemCounters{}, fmt.Errorf("lookup mem_counters: %w", err)
	}
	return c, nil
}

func (t *MemoryTracer) Close() error {
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
		t.cmap = nil
	}
	return nil
}
