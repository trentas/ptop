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
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/trentas/ptop/pkg/symbol"
)

// UprobeTrapCost is what a uprobe costs the thread that trips it on this host,
// beyond whatever the attached program itself does (#154): the trap into the
// kernel at the probed instruction, and for a uretprobe the second trap at the
// return. Measured, not assumed, because it differs by CPU and kernel by more
// than any constant could cover.
type UprobeTrapCost struct {
	EntryNs  float64 // a uprobe's trap, with an empty program
	ReturnNs float64 // a uretprobe's extra trap, with an empty program
	Calls    int     // calls per measurement
}

// calibrationTarget is the function the calibration probes. It does nothing,
// and is never inlined, so a call is one probed instruction and a return.
//
//go:noinline
func calibrationTarget(x uint64) uint64 { return x + 1 }

var calibrationSink uint64

const calibrationCalls = 20_000

// CalibrateUprobeTraps attaches an empty uprobe, then an empty uretprobe, to a
// function in this process and times calls to it against calls with nothing
// attached. Each figure is the smallest of a few rounds: noise only ever adds
// time.
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
	measure := func(prog string, ret bool) (float64, error) {
		p := coll.Programs[prog]
		if p == nil {
			return 0, fmt.Errorf("program %s missing", prog)
		}
		var l link.Link
		if ret {
			l, err = ex.Uretprobe("calibrationTarget", p, opts)
		} else {
			l, err = ex.Uprobe("calibrationTarget", p, opts)
		}
		if err != nil {
			return 0, uprobeAttachError("attach calibration probe", err)
		}
		defer l.Close()
		return timeCalls() - bare, nil
	}
	entry, err := measure("calib_entry", false)
	if err != nil {
		return UprobeTrapCost{}, err
	}
	ret, err := measure("calib_return", true)
	if err != nil {
		return UprobeTrapCost{}, err
	}
	// A uretprobe also traps at the entry, to hijack the return address; what
	// it adds beyond a uprobe's trap is the second one.
	return UprobeTrapCost{EntryNs: max(entry, 0), ReturnNs: max(ret-entry, 0), Calls: calibrationCalls}, nil
}

// timeCalls is the smallest per-call time of a few rounds of calls.
func timeCalls() float64 {
	var rounds []float64
	for r := 0; r < 5; r++ {
		start := time.Now()
		for i := uint64(0); i < calibrationCalls; i++ {
			calibrationSink += calibrationTarget(i)
		}
		rounds = append(rounds, float64(time.Since(start).Nanoseconds())/calibrationCalls)
	}
	return slices.Min(rounds)
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
