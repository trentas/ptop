//go:build linux && ebpf

package bpf

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// ThreadsTracer loads threads.bpf.o, attaches sched:sched_switch and
// sched:sched_wakeup, and exposes Totals() to read tid_state (keyed by the
// target's namespace-local TIDs) and RunqHistogram().
type ThreadsTracer struct {
	coll     *ebpf.Collection
	links    []link.Link
	stateMap *ebpf.Map
	histMap  *ebpf.Map
}

func OpenThreadsTracer(target Target) (*ThreadsTracer, error) {
	if err := target.validate(); err != nil {
		return nil, err
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
	tf, err := resolveTarget(target)
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

	t.histMap = coll.Maps["runq_hist"]
	if t.histMap == nil {
		t.Close()
		return nil, errors.New("runq_hist map missing")
	}

	// sched_wakeup ends a sleep where it ends, so the wait for a CPU after it
	// is run-queue time (#151).
	for _, tp := range []struct{ name, prog string }{
		{"sched_switch", "handle_sched_switch"},
		{"sched_wakeup", "handle_sched_wakeup"},
	} {
		prog := coll.Programs[tp.prog]
		if prog == nil {
			t.Close()
			return nil, fmt.Errorf("%s program missing", tp.prog)
		}
		l, err := link.Tracepoint("sched", tp.name, prog, nil)
		if err != nil {
			t.Close()
			return nil, fmt.Errorf("attach sched/%s: %w", tp.name, err)
		}
		t.links = append(t.links, l)
	}

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

// Totals returns each known thread's on-CPU, asleep and run-queue time since
// the tracer attached, with the interval still open added up to the moment
// that thread's entry was read (ThreadTotals.At). Keyed by the target's
// namespace-local TIDs. A thread absent from the result has not been switched
// out since the attach (see threads.bpf.c).
//
// The clock is read right after each entry is copied, so every stamp in it
// is at or before At and the open part is never negative.
func (t *ThreadsTracer) Totals() (map[uint32]ThreadTotals, error) {
	if t == nil || t.stateMap == nil {
		return nil, errors.New("tracer not initialized")
	}
	out := make(map[uint32]ThreadTotals, 64)
	var k uint32
	var v ThreadState
	iter := t.stateMap.Iterate()
	for iter.Next(&k, &v) {
		at, err := monotonicNanos()
		if err != nil {
			return out, err
		}
		out[k] = v.closeAt(at)
	}
	if err := iter.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// RunqHistogram sums the per-CPU run-queue histogram: every wait for a CPU
// the target's threads finished since the attach (#151).
func (t *ThreadsTracer) RunqHistogram() (RunqHist, error) {
	var out RunqHist
	if t == nil || t.histMap == nil {
		return out, errors.New("tracer not initialized")
	}
	var key uint32
	var perCPU []RunqHist
	if err := t.histMap.Lookup(&key, &perCPU); err != nil {
		return out, err
	}
	for _, h := range perCPU {
		for i := range out.Bucket {
			out.Bucket[i] += h.Bucket[i]
		}
		out.Count += h.Count
		out.SumNs += h.SumNs
	}
	return out, nil
}

func (t *ThreadsTracer) Close() error {
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
		t.stateMap = nil
	}
	return nil
}
