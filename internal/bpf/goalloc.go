//go:build linux && ebpf

package bpf

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/trentas/ptop/pkg/symbol"
)

//go:embed programs/goalloc.bpf.o
var goallocBPFObj []byte

// goallocStackDepth mirrors GOALLOC_STACK_DEPTH in programs/goalloc.bpf.c.
const goallocStackDepth = 32

// GoAllocFlagLarge mirrors GOALLOC_FLAG_LARGE: the allocation is ≥ 32KB, Go's
// large-object boundary (maxSmallSize).
const GoAllocFlagLarge uint32 = 1

// goMallocSymbol is the single funnel every Go heap allocation passes through.
// newobject, makeslice, growslice and reflect.unsafe_New all call it, and the
// size-specialised fast paths are dispatched from inside its body — so one
// entry probe sees every allocation exactly once.
//
// Its signature is load-bearing and the runtime says so: mallocgc is marked
// //go:linkname with a "Do not remove or change the type signature" comment
// (go.dev/issue/67401) because packages in the wild link against it. That makes
// it a far more stable attach point than any of the internal fast paths, whose
// names and arities have changed within the 1.2x series.
const goMallocSymbol = "runtime.mallocgc"

// GoAllocEvent is the 1:1 layout of struct go_alloc_event in
// programs/goalloc.bpf.c. Fixed 48 bytes.
//
// Size is the sampled allocation's own size; WeightBytes/WeightCount are what
// it stands for — everything accumulated since the previous sample on that CPU.
// With sampling off they are Size and 1.
type GoAllocEvent struct {
	TsNs        uint64
	Size        uint64
	WeightBytes uint64
	WeightCount uint64
	StackID     int32
	Flags       uint32
	TGID        uint32
	_           uint32
}

// goAllocEventSize is sizeof(struct go_alloc_event).
const goAllocEventSize = 48

// goAllocAccum mirrors struct goalloc_accum. Only the running totals are read
// from userspace; bytes/count belong to the kernel's sampling decision.
type goAllocAccum struct {
	Bytes      uint64
	Count      uint64
	Next       uint64
	TotalBytes uint64
	TotalCount uint64
}

// GoAllocCallSiteRaw mirrors struct go_callsite_stat — the kernel-maintained
// per-call-site aggregate. Everything here is monotonic: no counter decrements,
// because no free is observable (see goalloc.bpf.c).
type GoAllocCallSiteRaw struct {
	AllocCount uint64
	AllocBytes uint64
	LargeCount uint64
}

// GoAllocTracer loads goalloc.bpf.o and attaches one uprobe to
// runtime.mallocgc in the target's own executable, exposing the per-call-site
// allocation aggregate and the event stream.
//
// It reports allocation rate and volume per site, never live bytes or
// lifetime — see the header comment in goalloc.bpf.c for why that is the
// honest surface rather than a missing feature.
type GoAllocTracer struct {
	coll        *ebpf.Collection
	links       []link.Link
	rb          *ringbuf.Reader
	callsiteMap *ebpf.Map
	stacksMap   *ebpf.Map
	accumMap    *ebpf.Map
	sampleBytes uint64
}

// Totals returns how many allocations the target has made and how many bytes
// they came to, since the tracer attached. Counted in the kernel on EVERY
// allocation, sampled or not, so the allocation rate derived from these is
// exact and smooth whatever the sampling rate is — unlike one derived from the
// event stream, which would go lumpy below one sample per publish interval and
// would also miss whatever the ring buffer dropped.
func (t *GoAllocTracer) Totals() (count, bytes uint64, err error) {
	if t == nil || t.accumMap == nil {
		return 0, 0, errors.New("tracer not initialized")
	}
	var key uint32
	vals := make([]goAllocAccum, ebpf.MustPossibleCPU())
	if err := t.accumMap.Lookup(&key, &vals); err != nil {
		return 0, 0, err
	}
	for _, v := range vals {
		count += v.TotalCount
		bytes += v.TotalBytes
	}
	return count, bytes, nil
}

// SampleBytes is the rate the probe was opened with: bytes of allocation
// between recorded samples, 0 when every allocation is recorded. Reported so a
// consumer can tell an exact per-site figure from an estimated one.
func (t *GoAllocTracer) SampleBytes() uint64 {
	if t == nil {
		return 0
	}
	return t.sampleBytes
}

// ErrNotGo reports that the target's executable is not a Go image, so the Go
// allocation lane does not apply. Callers fall back to the libc lane.
var ErrNotGo = errors.New("target is not a Go binary")

// OpenGoAllocTracer attaches the Go allocation probe to pid, recording one
// stack per sampleBytes of allocation (0 = every allocation; see
// GoAllocDefaultSampleBytes).
//
// Returns ErrNotGo when the target's executable carries no Go line table, so
// the caller can fall back to the libc heap lane without treating it as a
// failure.
func OpenGoAllocTracer(pid int, sampleBytes uint64) (*GoAllocTracer, error) {
	if pid <= 0 {
		return nil, errors.New("invalid pid")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit: %w", err)
	}

	// /proc/<pid>/exe rather than the mapped path from /proc/<pid>/maps: the
	// magic link resolves to the running image even when the target lives in
	// another mount namespace (a container), and it cannot go stale the way a
	// path can after an upgrade replaces the file on disk.
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	mallocOff, err := goMallocFileOffset(exePath)
	if err != nil {
		return nil, err
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(goallocBPFObj))
	if err != nil {
		return nil, fmt.Errorf("parse goalloc BPF object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load goalloc collection: %w", err)
	}
	t := &GoAllocTracer{coll: coll}

	targetMap := coll.Maps["goalloc_target_pid"]
	if targetMap == nil {
		t.Close()
		return nil, errors.New("goalloc_target_pid map missing")
	}
	tf, err := resolveTarget(TargetPID(pid))
	if err != nil {
		t.Close()
		return nil, err
	}
	if err := writeTargetFilter(targetMap, tf); err != nil {
		t.Close()
		return nil, fmt.Errorf("set goalloc_target_pid: %w", err)
	}

	t.callsiteMap = coll.Maps["goalloc_callsite"]
	t.stacksMap = coll.Maps["goalloc_stacks"]
	t.accumMap = coll.Maps["goalloc_accum"]
	if t.callsiteMap == nil || t.stacksMap == nil || t.accumMap == nil {
		t.Close()
		return nil, errors.New("goalloc maps missing")
	}

	// The sampling rate goes in before the probe is attached, so no allocation
	// is ever observed under a rate the caller did not ask for.
	cfgMap := coll.Maps["goalloc_config"]
	if cfgMap == nil {
		t.Close()
		return nil, errors.New("goalloc_config map missing")
	}
	var zero uint32
	if err := cfgMap.Put(zero, sampleBytes); err != nil {
		t.Close()
		return nil, fmt.Errorf("set goalloc_config: %w", err)
	}
	t.sampleBytes = sampleBytes

	prog := coll.Programs["uprobe_go_mallocgc"]
	if prog == nil {
		t.Close()
		return nil, errors.New("program uprobe_go_mallocgc missing")
	}

	ex, err := link.OpenExecutable(exePath)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("open executable %s: %w", exePath, err)
	}
	// Address is supplied rather than letting the library resolve the symbol:
	// its resolver reads .symtab/.dynsym only, which a release build stripped
	// with -ldflags="-s -w" does not have. goMallocFileOffset falls back to
	// .gopclntab, which survives stripping.
	l, err := ex.Uprobe(goMallocSymbol, prog, &link.UprobeOptions{
		PID:     pid,
		Address: mallocOff,
	})
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("attach uprobe %s at file offset %#x: %w", goMallocSymbol, mallocOff, err)
	}
	t.links = append(t.links, l)

	eventsMap := coll.Maps["goalloc_events"]
	if eventsMap == nil {
		t.Close()
		return nil, errors.New("goalloc_events ringbuf missing")
	}
	rb, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}
	t.rb = rb

	return t, nil
}

// goMallocFileOffset locates runtime.mallocgc in the ELF image at path and
// returns its offset within the file, which is the form a uprobe takes.
//
// Returns ErrNotGo when the image has no Go line table.
func goMallocFileOffset(path string) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	mod, err := symbol.OpenModule(f, path)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", path, err)
	}
	if !mod.IsGo() {
		return 0, ErrNotGo
	}
	vaddr, _, ok := mod.FuncStart(goMallocSymbol)
	if !ok {
		// A Go image whose line table does not name mallocgc is either far
		// older than the register ABI this probe reads, or so heavily
		// rewritten that guessing would be worse than declining.
		return 0, fmt.Errorf("%s not found in %s (unsupported Go build)", goMallocSymbol, path)
	}
	off, ok := mod.FileOffset(vaddr)
	if !ok {
		return 0, fmt.Errorf("%s at %#x is in no file-backed segment of %s", goMallocSymbol, vaddr, path)
	}
	return off, nil
}

// Next blocks until the next allocation event arrives. Returns io.EOF when the
// tracer is closed.
func (t *GoAllocTracer) Next() (GoAllocEvent, error) {
	var ev GoAllocEvent
	if t == nil || t.rb == nil {
		return ev, errors.New("tracer not initialized")
	}
	rec, err := t.rb.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return ev, io.EOF
		}
		return ev, err
	}
	if len(rec.RawSample) < goAllocEventSize {
		return ev, fmt.Errorf("short event: %d bytes", len(rec.RawSample))
	}
	if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
		return ev, fmt.Errorf("decode event: %w", err)
	}
	return ev, nil
}

// CallSites snapshots goalloc_callsite: stack_id → running aggregate.
func (t *GoAllocTracer) CallSites() (map[int32]GoAllocCallSiteRaw, error) {
	if t == nil || t.callsiteMap == nil {
		return nil, errors.New("tracer not initialized")
	}
	out := make(map[int32]GoAllocCallSiteRaw, 64)
	var k int32
	var v GoAllocCallSiteRaw
	iter := t.callsiteMap.Iterate()
	for iter.Next(&k, &v) {
		out[k] = v
	}
	return out, iter.Err()
}

// ResolveStack returns the user-stack frames captured for stackID (leaf first),
// trailing zero slots trimmed. A negative id (capture failed) yields nil.
func (t *GoAllocTracer) ResolveStack(stackID int32) ([]uint64, error) {
	if stackID < 0 {
		return nil, nil
	}
	if t == nil || t.stacksMap == nil {
		return nil, errors.New("tracer not initialized")
	}
	var frames [goallocStackDepth]uint64
	if err := t.stacksMap.Lookup(uint32(stackID), &frames); err != nil {
		return nil, err
	}
	n := len(frames)
	for n > 0 && frames[n-1] == 0 {
		n--
	}
	return frames[:n], nil
}

func (t *GoAllocTracer) Close() error {
	if t == nil {
		return nil
	}
	if t.rb != nil {
		_ = t.rb.Close()
		t.rb = nil
	}
	for _, l := range t.links {
		_ = l.Close()
	}
	t.links = nil
	if t.coll != nil {
		t.coll.Close()
		t.coll = nil
		t.callsiteMap = nil
		t.stacksMap = nil
	}
	return nil
}
