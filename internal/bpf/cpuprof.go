//go:build linux && ebpf

package bpf

import (
	"bytes"
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// CPUProfiler samples the target's user stacks through a perf_event on every
// online CPU, so the CPU axis can name a function and not only a magnitude
// (#125). See programs/cpuprof.bpf.c for why this sits BESIDE the nanosecond
// axis rather than replacing it: the scheduler measures how much, and sampling
// is the only affordable way to know where.
//
// This is the mechanism #108 retired as an intensity meter, restored for the
// question it was always the right instrument for. The loader is essentially
// the pre-#108 one (perf_event_open per online CPU, PERF_EVENT_IOC_SET_BPF,
// PERF_EVENT_IOC_ENABLE), with the counter replaced by a stack aggregate and
// the requested rate now published beside the achieved one.
type CPUProfiler struct {
	coll    *ebpf.Collection
	counts  *ebpf.Map // cpuprof_counts: stack_id → samples
	stacks  *ebpf.Map // cpuprof_stacks: STACK_TRACE
	rate    *ebpf.Map // cpuprof_rate: per-CPU {fired, hit}
	perfFDs []int     // one per online CPU
	ncpu    int
	hz      int
}

// cpuprofStackDepth mirrors CPUPROF_STACK_DEPTH in the C.
const cpuprofStackDepth = 32

// cpuProfRateStat mirrors struct cpuprof_rate_stat. Keep byte-for-byte.
type cpuProfRateStat struct {
	Fired uint64
	Hit   uint64
}

// CPUProfRate is the sampler's own bookkeeping over the whole capture: every
// sample the PMU delivered (Fired, on all CPUs) and the subset that caught the
// target running (Hit).
//
// Fired is what makes the ACHIEVED rate a measurement. #108 established that
// the requested frequency is not the delivered one — in freq mode the kernel
// re-derives the period from what it sees at scheduler ticks, which do not run
// on an idle CPU, so a lightly loaded host delivers 80-90Hz where 100 was
// asked and drifts between windows. Dividing by the requested rate was half of
// what made the old CPU axis wrong; here the requested rate is never divided by
// at all, and the delivered one is reported.
type CPUProfRate struct {
	Fired uint64
	Hit   uint64
}

// OpenCPUProfiler attaches the sampler to target at hz samples per second per
// CPU. hz is taken as given — call NormalizeCPUProfHz first if it came from an
// operator.
func OpenCPUProfiler(target Target, hz int) (*CPUProfiler, error) {
	if err := target.validate(); err != nil {
		return nil, err
	}
	if hz <= 0 {
		return nil, fmt.Errorf("cpuprof: sampling rate %d is not a rate", hz)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit.RemoveMemlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(cpuprofBPFObj))
	if err != nil {
		return nil, fmt.Errorf("parse cpuprof BPF object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load cpuprof BPF collection: %w", err)
	}
	p := &CPUProfiler{coll: coll, hz: hz}

	targetMap := coll.Maps["cpuprof_target_pid"]
	if targetMap == nil {
		p.Close()
		return nil, errors.New("cpuprof_target_pid map not found")
	}
	tf, err := resolveTarget(target)
	if err != nil {
		p.Close()
		return nil, err
	}
	if err := writeTargetFilter(targetMap, tf); err != nil {
		p.Close()
		return nil, fmt.Errorf("set cpuprof_target_pid: %w", err)
	}

	p.counts = coll.Maps["cpuprof_counts"]
	p.stacks = coll.Maps["cpuprof_stacks"]
	p.rate = coll.Maps["cpuprof_rate"]
	if p.counts == nil || p.stacks == nil || p.rate == nil {
		p.Close()
		return nil, errors.New("cpuprof_counts / cpuprof_stacks / cpuprof_rate map not found")
	}

	prog := coll.Programs["handle_cpu_sample"]
	if prog == nil {
		p.Close()
		return nil, errors.New("handle_cpu_sample program not found")
	}

	// One event per ONLINE cpu, by id — not runtime.NumCPU(), which reports
	// the size of ptop's own affinity mask and would leave the target's time
	// on the rest of the machine unsampled whenever ptop is confined to a
	// cpuset (#108). Ids and not just a count: hot-unplug leaves gaps.
	cpus, err := onlineCPUs()
	if err != nil {
		p.Close()
		return nil, err
	}
	p.ncpu = len(cpus)
	for _, cpu := range cpus {
		attr := unix.PerfEventAttr{
			Type:        unix.PERF_TYPE_SOFTWARE,
			Config:      unix.PERF_COUNT_SW_CPU_CLOCK,
			Sample:      uint64(hz),
			Sample_type: unix.PERF_SAMPLE_RAW,
			// Sample is a frequency in Hz, not a period in nanoseconds. What
			// the kernel then actually delivers is a separate question, which
			// is why CPUProfRate.Fired exists.
			Bits: unix.PerfBitFreq,
		}
		attr.Size = uint32(unsafe.Sizeof(attr))
		// pid=-1 (any task), cpu=N, group_fd=-1: sample the whole CPU and let
		// pid_is_target() in the program decide. Per-target-thread events
		// would need every thread tracked as it spawns, and would not work at
		// all in cgroup mode, where the point is that no pid is known ahead of
		// time.
		fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if err != nil {
			p.Close()
			return nil, fmt.Errorf("perf_event_open cpu=%d: %w", cpu, err)
		}
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, prog.FD()); err != nil {
			unix.Close(fd)
			p.Close()
			return nil, fmt.Errorf("ioctl SET_BPF cpu=%d: %w", cpu, err)
		}
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			unix.Close(fd)
			p.Close()
			return nil, fmt.Errorf("ioctl ENABLE cpu=%d: %w", cpu, err)
		}
		p.perfFDs = append(p.perfFDs, fd)
	}

	return p, nil
}

// Samples drains the per-stack sample counts and CLEARS them, so each call
// returns exactly the window since the previous one. A negative key is a stack
// walk that failed; the caller reports those as an unresolved count rather
// than as a call site.
//
// Read-and-delete rather than cumulative-and-diff, for two reasons. The kernel
// hash is bounded (8192 entries): left to accumulate, a long capture fills it
// with stacks that stopped being sampled hours ago and then silently refuses
// new ones. And a window is what this axis means — a share computed over the
// whole capture hides a regression that started a minute ago.
//
// The read and the delete are two passes rather than one interleaved walk:
// deleting the key the iterator just returned makes the kernel's get_next_key
// restart from the first bucket, which can yield duplicates or loop. The cost
// is that samples landing between the two passes are deleted uncounted —
// bounded by how long the walk takes (milliseconds) against a window of about
// a second, and paid only by stacks that are being sampled right now.
func (p *CPUProfiler) Samples() (map[int32]uint64, error) {
	if p == nil || p.counts == nil {
		return nil, errors.New("profiler not initialized")
	}
	out := make(map[int32]uint64, 64)
	var k int32
	var v uint64
	iter := p.counts.Iterate()
	for iter.Next(&k, &v) {
		out[k] = v
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	for k := range out {
		key := k
		// A key deleted under us (it cannot be, today — nothing else deletes)
		// is not an error worth failing a window over.
		_ = p.counts.Delete(&key)
	}
	return out, nil
}

// Rate returns the sampler's cumulative delivery counts, summed over CPUs. The
// collector turns the delta into the achieved per-CPU frequency.
func (p *CPUProfiler) Rate() (CPUProfRate, error) {
	if p == nil || p.rate == nil {
		return CPUProfRate{}, errors.New("profiler not initialized")
	}
	var key uint32
	var perCPU []cpuProfRateStat
	if err := p.rate.Lookup(&key, &perCPU); err != nil {
		return CPUProfRate{}, err
	}
	var r CPUProfRate
	for _, s := range perCPU {
		r.Fired += s.Fired
		r.Hit += s.Hit
	}
	return r, nil
}

// ResolveStack returns the user-stack frames captured for stackID (leaf first),
// trailing zero slots trimmed. A negative id (the walk failed) yields nil.
func (p *CPUProfiler) ResolveStack(stackID int32) ([]uint64, error) {
	if stackID < 0 {
		return nil, nil
	}
	if p == nil || p.stacks == nil {
		return nil, errors.New("profiler not initialized")
	}
	var frames [cpuprofStackDepth]uint64
	if err := p.stacks.Lookup(uint32(stackID), &frames); err != nil {
		return nil, err
	}
	n := len(frames)
	for n > 0 && frames[n-1] == 0 {
		n--
	}
	return frames[:n], nil
}

// RequestedHz is the per-CPU rate the sampler asked the kernel for. It is
// reported beside the achieved rate and never divided by — see CPUProfRate.
func (p *CPUProfiler) RequestedHz() int {
	if p == nil {
		return 0
	}
	return p.hz
}

// NumCPU is how many CPUs the sampler opened an event on — the divisor that
// turns Fired into a per-CPU frequency.
func (p *CPUProfiler) NumCPU() int {
	if p == nil {
		return 0
	}
	return p.ncpu
}

func (p *CPUProfiler) Close() error {
	if p == nil {
		return nil
	}
	for _, fd := range p.perfFDs {
		_ = unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_DISABLE, 0)
		_ = unix.Close(fd)
	}
	p.perfFDs = nil
	if p.coll != nil {
		p.coll.Close()
		p.coll = nil
		p.counts, p.stacks, p.rate = nil, nil, nil
	}
	return nil
}
