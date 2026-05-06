//go:build linux && ebpf

package bpf

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:embed programs/cpu.bpf.o
var cpuBPFObj []byte

// CPUTracer samples the target PID via perf_event PERF_COUNT_SW_CPU_CLOCK
// at SAMPLE_FREQ Hz per CPU. When the kernel fires a sample and the current
// tgid is the target, the BPF program increments a counter. The collector
// reads the counter every N seconds and computes CPU %.
type CPUTracer struct {
	coll       *ebpf.Collection
	samplesMap *ebpf.Map
	perfFDs    []int // 1 fd per online CPU
}

// SampleFreq is the sampling frequency in Hz per CPU. 100Hz is what
// `perf record` uses by default and what macOS Instruments calls the
// "Sampler" — granular enough to detect CPU spikes >10ms.
const SampleFreq = 100

func OpenCPUTracer(pid int) (*CPUTracer, error) {
	if pid <= 0 {
		return nil, errors.New("invalid pid")
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

	t := &CPUTracer{coll: coll}

	targetMap := coll.Maps["cpu_target_pid"]
	if targetMap == nil {
		t.Close()
		return nil, errors.New("cpu_target_pid map not found")
	}
	var key uint32 = 0
	val := uint32(pid)
	if err := targetMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
		t.Close()
		return nil, fmt.Errorf("set cpu_target_pid: %w", err)
	}

	t.samplesMap = coll.Maps["cpu_target_samples"]
	if t.samplesMap == nil {
		t.Close()
		return nil, errors.New("cpu_target_samples map not found")
	}

	prog := coll.Programs["handle_perf_event"]
	if prog == nil {
		t.Close()
		return nil, errors.New("handle_perf_event program not found")
	}

	// perf_event_open + ioctl(PERF_EVENT_IOC_SET_BPF) per CPU.
	// PERF_TYPE_SOFTWARE/PERF_COUNT_SW_CPU_CLOCK fires samples at
	// SAMPLE_FREQ Hz per CPU (kernel guarantees uniformity).
	ncpu := runtime.NumCPU()
	for cpu := 0; cpu < ncpu; cpu++ {
		attr := unix.PerfEventAttr{
			Type:        unix.PERF_TYPE_SOFTWARE,
			Config:      unix.PERF_COUNT_SW_CPU_CLOCK,
			Sample:      SampleFreq,
			Sample_type: unix.PERF_SAMPLE_RAW,
			Bits:        unix.PerfBitFreq, // Sample is a rate (Hz), not a period in ns
		}
		attr.Size = uint32(unsafe.Sizeof(attr))
		// pid=-1 (any task), cpu=cpu, group_fd=-1
		fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, 0)
		if err != nil {
			t.Close()
			return nil, fmt.Errorf("perf_event_open cpu=%d: %w", cpu, err)
		}
		// Attach BPF program to this fd
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, prog.FD()); err != nil {
			unix.Close(fd)
			t.Close()
			return nil, fmt.Errorf("ioctl SET_BPF cpu=%d: %w", cpu, err)
		}
		// Enable sampling
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			unix.Close(fd)
			t.Close()
			return nil, fmt.Errorf("ioctl ENABLE cpu=%d: %w", cpu, err)
		}
		t.perfFDs = append(t.perfFDs, fd)
	}

	return t, nil
}

// SampleCount returns the current accumulated count of on-CPU samples.
// The collector uses the delta between calls to compute %.
func (t *CPUTracer) SampleCount() (uint64, error) {
	if t == nil || t.samplesMap == nil {
		return 0, errors.New("tracer not initialized")
	}
	var key uint32 = 0
	var val uint64
	if err := t.samplesMap.Lookup(&key, &val); err != nil {
		return 0, err
	}
	return val, nil
}

// NumCPU returns the number of CPUs the tracer is sampling on.
// Used by the collector for the % computation.
func (t *CPUTracer) NumCPU() int {
	return len(t.perfFDs)
}

func (t *CPUTracer) Close() error {
	if t == nil {
		return nil
	}
	for _, fd := range t.perfFDs {
		// Disable then close
		_ = unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_DISABLE, 0)
		_ = unix.Close(fd)
	}
	t.perfFDs = nil
	if t.coll != nil {
		t.coll.Close()
		t.coll = nil
		t.samplesMap = nil
	}
	return nil
}
