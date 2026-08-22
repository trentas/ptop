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

// futexStackDepth mirrors FUTEX_STACK_DEPTH in programs/futex.bpf.c — the user
// stack depth captured at a contention site.
const futexStackDepth = 32

// FutexKey mirrors `struct futex_key`: the futex word plus the user stack
// captured where a thread blocked on it (#89). Waits are counted per
// (lock, contention site) so a lock keeps an identity that survives ASLR —
// uaddr alone does not. StackID is -1 on wake-class calls (no stack is walked)
// and on a failed walk.
type FutexKey struct {
	UAddr   uint64
	StackID int32
	_       uint32 // struct futex_key's explicit pad; part of the hash key
}

// FutexStat mirrors `struct futex_stat` in programs/futex.bpf.c 1:1.
// 40 bytes (4 × u64 + 2 × u32).
type FutexStat struct {
	WaitCount   uint64
	WakeCount   uint64
	LatSumNs    uint64
	LatCount    uint64
	LastWaitTID uint32
	LastWakeTID uint32
}

// FutexTracer loads futex.bpf.o, attaches sys_enter/exit_futex and exposes
// Stats() to read the futex_stats map keyed by (uaddr, contention site), plus
// ResolveStack() for that site's frames.
type FutexTracer struct {
	coll      *ebpf.Collection
	links     []link.Link
	smap      *ebpf.Map
	stacksMap *ebpf.Map
}

func OpenFutexTracer(target Target) (*FutexTracer, error) {
	if err := target.validate(); err != nil {
		return nil, err
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
		return nil, errors.New("futex_target_pid map missing")
	}
	tf, err := resolveTarget(target)
	if err != nil {
		t.Close()
		return nil, err
	}
	if err := writeTargetFilter(targetMap, tf); err != nil {
		t.Close()
		return nil, fmt.Errorf("set futex_target_pid: %w", err)
	}

	t.smap = coll.Maps["futex_stats"]
	t.stacksMap = coll.Maps["futex_stacks"]
	if t.smap == nil || t.stacksMap == nil {
		t.Close()
		return nil, errors.New("futex maps missing")
	}

	tracepoints := []struct{ group, name, prog string }{
		{"syscalls", "sys_enter_futex", "handle_enter_futex"},
		{"syscalls", "sys_exit_futex", "handle_exit_futex"},
	}
	for _, tp := range tracepoints {
		p := coll.Programs[tp.prog]
		if p == nil {
			t.Close()
			return nil, fmt.Errorf("program %s missing", tp.prog)
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

// Stats returns a complete snapshot of the futex_stats map:
// (uaddr, contention site) → stat.
func (t *FutexTracer) Stats() (map[FutexKey]FutexStat, error) {
	if t == nil || t.smap == nil {
		return nil, errors.New("tracer not initialized")
	}
	out := make(map[FutexKey]FutexStat, 64)
	var k FutexKey
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

// ResolveStack returns the user-stack frames captured for stackID (leaf first),
// trailing zero slots trimmed. A negative id (wake op, or a failed walk) yields
// nil. Mirrors HeapTracer.ResolveStack.
func (t *FutexTracer) ResolveStack(stackID int32) ([]uint64, error) {
	if stackID < 0 {
		return nil, nil
	}
	if t == nil || t.stacksMap == nil {
		return nil, errors.New("tracer not initialized")
	}
	var frames [futexStackDepth]uint64
	if err := t.stacksMap.Lookup(uint32(stackID), &frames); err != nil {
		return nil, err
	}
	n := len(frames)
	for n > 0 && frames[n-1] == 0 {
		n--
	}
	return frames[:n], nil
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
		t.stacksMap = nil
	}
	return nil
}
