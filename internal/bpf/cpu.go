//go:build linux && ebpf

package bpf

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:embed programs/cpu.bpf.o
var cpuBPFObj []byte

// CPUTracer accumulates how many nanoseconds the target spent on-CPU, by
// bracketing its scheduler slices at sched:sched_switch (see programs/cpu.bpf.c
// for the mechanism and for why this is not a sampler any more, #108).
//
// The collector reads OnCPUNanos every second and divides by the elapsed wall
// time; the result is the same quantity /proc reports as utime+stime, so the
// two agree by construction instead of by luck.
type CPUTracer struct {
	coll  *ebpf.Collection
	link  link.Link
	acc   *ebpf.Map // cpu_oncpu_ns, per-CPU
	since *ebpf.Map // cpu_on_since, per-CPU
	ncpu  int
}

func OpenCPUTracer(target Target) (*CPUTracer, error) {
	if err := target.validate(); err != nil {
		return nil, err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit.RemoveMemlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(cpuBPFObj))
	if err != nil {
		return nil, fmt.Errorf("parse cpu BPF object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load cpu BPF collection: %w", err)
	}

	cpus, err := onlineCPUs()
	if err != nil {
		coll.Close()
		return nil, err
	}
	t := &CPUTracer{coll: coll, ncpu: len(cpus)}

	targetMap := coll.Maps["cpu_target_pid"]
	if targetMap == nil {
		t.Close()
		return nil, errors.New("cpu_target_pid map not found")
	}
	tf, err := resolveTarget(target)
	if err != nil {
		t.Close()
		return nil, err
	}
	if err := writeTargetFilter(targetMap, tf); err != nil {
		t.Close()
		return nil, fmt.Errorf("set cpu_target_pid: %w", err)
	}

	t.acc = coll.Maps["cpu_oncpu_ns"]
	t.since = coll.Maps["cpu_on_since"]
	if t.acc == nil || t.since == nil {
		t.Close()
		return nil, errors.New("cpu_oncpu_ns / cpu_on_since map not found")
	}

	prog := coll.Programs["handle_sched_switch"]
	if prog == nil {
		t.Close()
		return nil, errors.New("handle_sched_switch program not found")
	}
	l, err := link.Tracepoint("sched", "sched_switch", prog, nil)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("attach sched/sched_switch: %w", err)
	}
	t.link = l

	return t, nil
}

// onlineCPUs lists the ids of the CPUs the kernel currently has online.
//
// It is only the ceiling for the saturation clamp now that nothing is opened
// per CPU — but it stays a sysfs read rather than runtime.NumCPU(), which
// reports the size of PTOP's own affinity mask and would shrink the ceiling
// below what the target can actually use whenever ptop is confined to a cpuset
// (systemd CPUAffinity=, taskset, a container's cpuset).
func onlineCPUs() ([]int, error) {
	b, err := os.ReadFile("/sys/devices/system/cpu/online")
	if err == nil {
		ids, perr := parseCPUList(string(b))
		if perr != nil {
			return nil, fmt.Errorf("parse /sys/devices/system/cpu/online: %w", perr)
		}
		if len(ids) > 0 {
			return ids, nil
		}
	}
	n := runtime.NumCPU()
	if n < 1 {
		return nil, errors.New("no online CPUs")
	}
	ids := make([]int, n)
	for i := range ids {
		ids[i] = i
	}
	return ids, nil
}

// OnCPUNanos returns the target's total on-CPU time since the tracer attached.
//
// It is the sum of the finished slices the BPF program has accumulated plus
// the slice in flight on every CPU currently running a target thread —
// without that second term, a thread that runs for a whole window without
// being switched out would report zero for that window and a spike for the
// next one, which is the failure this axis is trying to stop reporting.
//
// The two maps are read in this order — accumulator, then clock, then the
// in-flight timestamps — so that a slice ending mid-read is either counted
// once in the accumulator or dropped from this reading and picked up by the
// next one. The reverse order can count the same nanoseconds twice and make
// the total go backwards.
func (t *CPUTracer) OnCPUNanos() (uint64, error) {
	if t == nil || t.acc == nil || t.since == nil {
		return 0, errors.New("tracer not initialized")
	}
	var key uint32

	var accPerCPU []uint64
	if err := t.acc.Lookup(&key, &accPerCPU); err != nil {
		return 0, err
	}
	now, err := monotonicNanos()
	if err != nil {
		return 0, err
	}
	var sincePerCPU []uint64
	if err := t.since.Lookup(&key, &sincePerCPU); err != nil {
		return 0, err
	}

	var total uint64
	for _, v := range accPerCPU {
		total += v
	}
	for _, s := range sincePerCPU {
		if s != 0 && now > s {
			total += now - s
		}
	}
	return total, nil
}

// monotonicNanos reads the clock bpf_ktime_get_ns() is based on
// (CLOCK_MONOTONIC — not CLOCK_BOOTTIME, which counts time spent suspended),
// so the in-flight slice above is measured in the same domain the BPF program
// timestamped it in.
func monotonicNanos() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, fmt.Errorf("clock_gettime(CLOCK_MONOTONIC): %w", err)
	}
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec), nil
}

// NumCPU returns how many CPUs are online — the ceiling the collector clamps
// its percentage to.
func (t *CPUTracer) NumCPU() int {
	if t == nil {
		return 0
	}
	return t.ncpu
}

func (t *CPUTracer) Close() error {
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
		t.acc = nil
		t.since = nil
	}
	return nil
}
