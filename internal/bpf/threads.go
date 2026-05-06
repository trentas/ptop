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

// ThreadsTracer loads threads.bpf.o, attaches sched:sched_switch, and
// exposes Stats() to read tid_state + UpdateTrackedTIDs() to update the
// set of TIDs the BPF program should track.
type ThreadsTracer struct {
	coll        *ebpf.Collection
	link        link.Link
	stateMap    *ebpf.Map
	trackedMap  *ebpf.Map
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
	var key uint32 = 0
	val := uint32(pid)
	if err := targetMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
		t.Close()
		return nil, fmt.Errorf("set threads_target_pid: %w", err)
	}

	t.stateMap = coll.Maps["tid_state"]
	t.trackedMap = coll.Maps["tracked_tids"]
	if t.stateMap == nil || t.trackedMap == nil {
		t.Close()
		return nil, errors.New("tid_state / tracked_tids map missing")
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

// UpdateTrackedTIDs syncs the tracked_tids map with the supplied slice.
// Adds new TIDs and removes ones that disappeared. Called periodically by
// the collector (Go side) — it already walks /proc/<pid>/task/ to collect
// state/wchan.
func (t *ThreadsTracer) UpdateTrackedTIDs(tids []int) error {
	if t == nil || t.trackedMap == nil {
		return errors.New("tracer not initialized")
	}
	desired := make(map[uint32]struct{}, len(tids))
	for _, tid := range tids {
		if tid > 0 {
			desired[uint32(tid)] = struct{}{}
		}
	}

	// List existing
	existing := make(map[uint32]struct{}, len(desired))
	var k uint32
	var v uint8
	iter := t.trackedMap.Iterate()
	for iter.Next(&k, &v) {
		existing[k] = struct{}{}
	}

	// Add missing
	for tid := range desired {
		if _, ok := existing[tid]; !ok {
			one := uint8(1)
			if err := t.trackedMap.Update(&tid, &one, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("add tid %d: %w", tid, err)
			}
		}
	}
	// Remove orphans
	for tid := range existing {
		if _, ok := desired[tid]; !ok {
			_ = t.trackedMap.Delete(&tid)
			// Also clear state so recycled TIDs don't inherit counters.
			_ = t.stateMap.Delete(&tid)
		}
	}
	return nil
}

// Stats returns a complete snapshot of the tid_state map.
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
		t.trackedMap = nil
	}
	return nil
}
