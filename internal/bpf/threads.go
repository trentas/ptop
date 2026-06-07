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

//go:embed programs/threads.bpf.o
var threadsBPFObj []byte

// ThreadState mirrors `struct thread_state` in programs/threads.bpf.c 1:1.
// 40 bytes aligned (5 × u64).
type ThreadState struct {
	LastOnCpuNs   uint64
	LastOffCpuNs  uint64
	OnCpuNsTotal  uint64
	OffCpuNsTotal uint64
	CtxSwitches   uint64
}

// ThreadsTracer loads threads.bpf.o, attaches sched:sched_switch, and exposes
// Stats() to read tid_state (keyed by the target's namespace-local TIDs).
type ThreadsTracer struct {
	coll     *ebpf.Collection
	link     link.Link
	stateMap *ebpf.Map
}

func OpenThreadsTracer(pid int) (*ThreadsTracer, error) {
	if pid <= 0 {
		return nil, errors.New("invalid pid")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(threadsBPFObj))
	if err != nil {
		return nil, fmt.Errorf("parse threads BPF object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load threads collection: %w", err)
	}
	t := &ThreadsTracer{coll: coll}

	targetMap := coll.Maps["threads_target_pid"]
	if targetMap == nil {
		t.Close()
		return nil, errors.New("threads_target_pid map missing")
	}
	tf, err := resolveTarget(pid)
	if err != nil {
		t.Close()
		return nil, err
	}
	if err := writeTargetFilter(targetMap, tf); err != nil {
		t.Close()
		return nil, fmt.Errorf("set threads_target_pid: %w", err)
	}

	t.stateMap = coll.Maps["tid_state"]
	if t.stateMap == nil {
		t.Close()
		return nil, errors.New("tid_state map missing")
	}

	prog := coll.Programs["handle_sched_switch"]
	if prog == nil {
		t.Close()
		return nil, errors.New("handle_sched_switch program missing")
	}
	l, err := link.Tracepoint("sched", "sched_switch", prog, nil)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("attach sched/sched_switch: %w", err)
	}
	t.link = l

	return t, nil
}

// PruneDeadTIDs deletes tid_state entries for TIDs no longer alive, so a
// recycled TID does not inherit stale counters. `live` holds the
// namespace-local TIDs currently present under /proc/<pid>/task/.
//
// The root2ns map is intentionally left unpruned: it is an LRU_HASH that
// evicts dead entries on its own, and a stale entry at worst produces a
// tid_state row the collector never publishes (it only emits TIDs found
// under /proc/<pid>/task/).
func (t *ThreadsTracer) PruneDeadTIDs(live []int) error {
	if t == nil || t.stateMap == nil {
		return errors.New("tracer not initialized")
	}
	alive := make(map[uint32]struct{}, len(live))
	for _, tid := range live {
		if tid > 0 {
			alive[uint32(tid)] = struct{}{}
		}
	}
	var dead []uint32
	var k uint32
	var v ThreadState // unused; the Iterate API requires a value pointer
	iter := t.stateMap.Iterate()
	for iter.Next(&k, &v) {
		if _, ok := alive[k]; !ok {
			dead = append(dead, k)
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for i := range dead {
		_ = t.stateMap.Delete(&dead[i])
	}
	return nil
}

// Stats returns a complete snapshot of the tid_state map, keyed by the
// target's namespace-local TIDs.
func (t *ThreadsTracer) Stats() (map[uint32]ThreadState, error) {
	if t == nil || t.stateMap == nil {
		return nil, errors.New("tracer not initialized")
	}
	out := make(map[uint32]ThreadState, 64)
	var k uint32
	var v ThreadState
	iter := t.stateMap.Iterate()
	for iter.Next(&k, &v) {
		out[k] = v
	}
	if err := iter.Err(); err != nil {
		return out, err
	}
	return out, nil
}

func (t *ThreadsTracer) Close() error {
	if t == nil {
		return nil
	}
	if t.link != nil {
		_ = t.link.Close()
		t.link = nil
	}
	if t.coll != nil {
		t.coll.Close()
		t.coll = nil
		t.stateMap = nil
	}
	return nil
}
