//go:build linux && ebpf

package bpf

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/trentas/ptop/pkg/symbol"
)

// UprobeTrapCost is what a uprobe costs the thread that trips it on this host,
// beyond whatever the attached program itself does (#154): the trap into the
// kernel at the probed instruction. Measured, not assumed, because it differs
// by CPU and kernel by more than any constant could cover (~485ns on the
// reference arm64 VM, ~2µs on a CI amd64 runner, same kernel).
//
// A uretprobe's extra trap at the return is not measured: timing one in ptop's
// own process would mean a uretprobe on a Go function, which rewrites a return
// address the Go runtime's stack walker reads (calib.bpf.c). ReturnNs stays 0.
type UprobeTrapCost struct {
	EntryNs  float64 // a uprobe's trap, with an empty program
	ReturnNs float64 // not measured: always 0, see above
	Calls    int     // calls per measurement
}

// calibrationTarget is the function the calibration probes. It does nothing,
// and is never inlined, so a call is one probed instruction and a return.
//
//go:noinline
func calibrationTarget(x uint64) uint64 { return x + 1 }

var calibrationSink uint64

const calibrationCalls = 20_000

// CalibrateUprobeTraps attaches an empty uprobe to a function in this process
// and times calls to it against calls with nothing attached. Each figure is the
// smallest of a few rounds: noise only ever adds time. Never a uretprobe: see
// UprobeTrapCost.
func CalibrateUprobeTraps() (UprobeTrapCost, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return UprobeTrapCost{}, fmt.Errorf("rlimit: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(calibBPFObj))
	if err != nil {
		return UprobeTrapCost{}, fmt.Errorf("parse calib BPF object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return UprobeTrapCost{}, fmt.Errorf("load calib collection: %w", err)
	}
	defer coll.Close()

	off, err := selfFuncOffset(calibrationTarget)
	if err != nil {
		return UprobeTrapCost{}, err
	}
	ex, err := link.OpenExecutable("/proc/self/exe")
	if err != nil {
		return UprobeTrapCost{}, fmt.Errorf("open own executable: %w", err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	opts := &link.UprobeOptions{PID: os.Getpid(), Address: off}

	bare := timeCalls()
	p := coll.Programs["calib_entry"]
	if p == nil {
		return UprobeTrapCost{}, errors.New("program calib_entry missing")
	}
	l, err := ex.Uprobe("calibrationTarget", p, opts)
	if err != nil {
		return UprobeTrapCost{}, uprobeAttachError("attach calibration probe", err)
	}
	entry := timeCalls() - bare
	_ = l.Close()
	return UprobeTrapCost{EntryNs: max(entry, 0), Calls: calibrationCalls}, nil
}

// timeCalls is the smallest per-call time of a few rounds of calls, by this
// thread's own CPU clock: the trap is CPU time the thread spends in the kernel,
// and the clock does not count time the thread waited for a CPU. Wall time
// did, and on a busy host it read the trap a quarter too long — enough to put
// an estimate above everything the target used (#154).
func timeCalls() float64 {
	var rounds []float64
	for r := 0; r < 5; r++ {
		start := threadCPU()
		for i := uint64(0); i < calibrationCalls; i++ {
			calibrationSink += calibrationTarget(i)
		}
		rounds = append(rounds, float64(threadCPU()-start)/calibrationCalls)
	}
	return slices.Min(rounds)
}

// threadCPU is the calling thread's CPU time in ns. The caller is locked to
// its thread.
func threadCPU() int64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &ts)
	return ts.Nano()
}

// selfFuncOffset is the file offset of a function of this binary, the form a
// uprobe takes. It reads .gopclntab, which survives `-s -w`.
func selfFuncOffset(fn any) (uint64, error) {
	pc := reflect.ValueOf(fn).Pointer()
	name := runtime.FuncForPC(pc).Name()
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	mod, err := symbol.OpenModule(f, "/proc/self/exe")
	if err != nil {
		return 0, fmt.Errorf("parse own executable: %w", err)
	}
	vaddr, _, ok := mod.FuncStart(name)
	if !ok {
		return 0, fmt.Errorf("%s not in own line table", name)
	}
	off, ok := mod.FileOffset(vaddr)
	if !ok {
		return 0, errors.New("calibration target is in no file-backed segment")
	}
	return off, nil
}
