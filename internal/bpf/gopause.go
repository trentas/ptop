//go:build linux && ebpf

package bpf

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/trentas/ptop/pkg/symbol"
)

// The Go runtime's entry and exit of a stop-the-world (#175).
const (
	goStopTheWorldSymbol  = "runtime.stopTheWorldWithSema"
	goStartTheWorldSymbol = "runtime.startTheWorldWithSema"
)

// GoPauseBuckets is the histogram width: bucket i counts the pauses of
// [2^i, 2^(i+1)) µs, bucket 0 also those under 1 µs, the last everything
// longer. Mirrors GOPAUSE_BUCKETS in programs/gopause.bpf.c.
const GoPauseBuckets = 32

// GoPauseTotals is the cumulative pause aggregate since the tracer attached.
// Mirrors struct gopause_totals.
type GoPauseTotals struct {
	Count   uint64
	SumNs   uint64
	Buckets [GoPauseBuckets]uint64
}

// GoPauseTracer times a Go target's stop-the-world pauses (#175). See
// programs/gopause.bpf.c for why two entry uprobes and no uretprobe.
type GoPauseTracer struct {
	coll   *ebpf.Collection
	totals *ebpf.Map
	links  []link.Link
}

// OpenGoPauseTracer attaches to the target's runtime. Returns ErrNotGo when the
// executable is not a Go image: a pause axis there is unsupported, never an
// empty one that reads as "no pause".
func OpenGoPauseTracer(pid int) (*GoPauseTracer, error) {
	if pid <= 0 {
		return nil, errors.New("invalid pid")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit: %w", err)
	}
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	stopOff, startOff, err := goPauseFileOffsets(exePath)
	if err != nil {
		if errors.Is(err, ErrNotGo) {
			return nil, err
		}
		return nil, targetReadError("locate the runtime's stop-the-world in the target executable", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(gopauseBPFObj))
	if err != nil {
		return nil, fmt.Errorf("parse gopause BPF object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, kprobeLoadError("load gopause collection", err)
	}
	t := &GoPauseTracer{coll: coll, totals: coll.Maps["gopause_totals"]}
	targetMap := coll.Maps["gopause_target_pid"]
	if targetMap == nil || t.totals == nil {
		t.Close()
		return nil, errors.New("gopause maps missing")
	}
	tf, err := resolveTarget(TargetPID(pid))
	if err != nil {
		t.Close()
		return nil, err
	}
	if err := writeTargetFilter(targetMap, tf); err != nil {
		t.Close()
		return nil, fmt.Errorf("set gopause_target_pid: %w", err)
	}

	ex, err := link.OpenExecutable(exePath)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("open executable %s: %w", exePath, err)
	}
	// The stop first would leave a window where a pause starts unseen and its
	// end finds no start; the restart first leaves only ends with no start,
	// which the program drops. So the end attaches before the start.
	for _, p := range []struct {
		prog, sym string
		off       uint64
	}{
		{"uprobe_go_start_the_world", goStartTheWorldSymbol, startOff},
		{"uprobe_go_stop_the_world", goStopTheWorldSymbol, stopOff},
	} {
		prog := coll.Programs[p.prog]
		if prog == nil {
			t.Close()
			return nil, fmt.Errorf("program %s missing", p.prog)
		}
		l, err := ex.Uprobe(p.sym, prog, &link.UprobeOptions{PID: pid, Address: p.off})
		if err != nil {
			t.Close()
			return nil, uprobeAttachError(fmt.Sprintf("attach uprobe %s at file offset %#x", p.sym, p.off), err)
		}
		t.links = append(t.links, l)
	}
	return t, nil
}

// goPauseFileOffsets locates the two runtime functions through .gopclntab,
// which survives -ldflags="-s -w", like goMallocFileOffset.
func goPauseFileOffsets(path string) (stop, start uint64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	mod, err := symbol.OpenModule(f, path)
	if err != nil {
		return 0, 0, fmt.Errorf("parse %s: %w", path, err)
	}
	if !mod.IsGo() {
		return 0, 0, ErrNotGo
	}
	offOf := func(sym string) (uint64, error) {
		vaddr, _, ok := mod.FuncStart(sym)
		if !ok {
			return 0, fmt.Errorf("%s not found in %s (unsupported Go build)", sym, path)
		}
		off, ok := mod.FileOffset(vaddr)
		if !ok {
			return 0, fmt.Errorf("%s at %#x is in no file-backed segment of %s", sym, vaddr, path)
		}
		return off, nil
	}
	if stop, err = offOf(goStopTheWorldSymbol); err != nil {
		return 0, 0, err
	}
	if start, err = offOf(goStartTheWorldSymbol); err != nil {
		return 0, 0, err
	}
	return stop, start, nil
}

// Totals reads the cumulative aggregate.
func (t *GoPauseTracer) Totals() (GoPauseTotals, error) {
	var v GoPauseTotals
	if t == nil || t.totals == nil {
		return v, errors.New("tracer not initialized")
	}
	var zero uint32
	if err := t.totals.Lookup(zero, &v); err != nil {
		return v, fmt.Errorf("read gopause_totals: %w", err)
	}
	return v, nil
}

// Close detaches the probes and releases the maps.
func (t *GoPauseTracer) Close() error {
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
	}
	return nil
}
