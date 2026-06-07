//go:build linux && ebpf

package bpf

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:embed programs/heap.bpf.o
var heapBPFObj []byte

// heapStackDepth mirrors HEAP_STACK_DEPTH in programs/heap.bpf.c — the user
// stack depth captured per call site.
const heapStackDepth = 32

// Op codes — mirror the OP_* defines in programs/heap.bpf.c.
const (
	HeapOpMalloc  uint32 = 0
	HeapOpCalloc  uint32 = 1
	HeapOpRealloc uint32 = 2
	HeapOpFree    uint32 = 3
)

// HeapFlagLarge mirrors HEAP_FLAG_LARGE: the allocation is ≥ 128KB.
const HeapFlagLarge uint32 = 1

// HeapEvent is the 1:1 layout of struct heap_event in programs/heap.bpf.c.
// Fixed 48 bytes; binary.LittleEndian.Read parses it from the ring buffer.
type HeapEvent struct {
	TsNs       uint64
	Size       uint64
	Addr       uint64
	LifetimeNs uint64
	StackID    int32
	Op         uint32
	Flags      uint32
	TGID       uint32
}

// allocInfo mirrors struct alloc_info — the per-pointer live record iterated
// during the leak scan.
type allocInfo struct {
	Size    uint64
	TsNs    uint64
	StackID int32
	_       uint32
}

// HeapCallSiteRaw mirrors struct callsite_stat — the kernel-maintained
// per-call-site aggregate. live_bytes/live_count are signed (a free decrements
// them); the collector clamps to ≥ 0 defensively.
type HeapCallSiteRaw struct {
	LiveBytes     int64
	LiveCount     int64
	AllocCount    uint64
	LifetimeSumNs uint64
	LifetimeCount uint64
	LargeCount    uint64
}

// HeapLeak is one live allocation whose age exceeds the leak threshold.
type HeapLeak struct {
	Size    uint64
	StackID int32
	AgeNs   uint64
}

// maxLeakScan bounds the per-pointer iteration so a pathological live set can't
// stall the publish loop. Equals heap_allocs' max_entries.
const maxLeakScan = 1 << 17

// HeapTracer loads heap.bpf.o, attaches uprobes/uretprobes on the target's
// libc allocator, opens the event ring buffer, and exposes the per-call-site
// aggregate, the leak scan, and stack resolution.
type HeapTracer struct {
	coll        *ebpf.Collection
	links       []link.Link
	rb          *ringbuf.Reader
	allocsMap   *ebpf.Map
	callsiteMap *ebpf.Map
	stacksMap   *ebpf.Map

	libcLo, libcHi uint64 // target VA range of the mapped libc
}

func OpenHeapTracer(pid int) (*HeapTracer, error) {
	if pid <= 0 {
		return nil, errors.New("invalid pid")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit: %w", err)
	}

	libcPath, lo, hi, err := resolveLibc(pid)
	if err != nil {
		return nil, err
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(heapBPFObj))
	if err != nil {
		return nil, fmt.Errorf("parse heap BPF object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load heap collection: %w", err)
	}
	t := &HeapTracer{coll: coll, libcLo: lo, libcHi: hi}

	targetMap := coll.Maps["heap_target_pid"]
	if targetMap == nil {
		t.Close()
		return nil, errors.New("heap_target_pid map missing")
	}
	tf, err := resolveTarget(pid)
	if err != nil {
		t.Close()
		return nil, err
	}
	if err := writeTargetFilter(targetMap, tf); err != nil {
		t.Close()
		return nil, fmt.Errorf("set heap_target_pid: %w", err)
	}

	t.allocsMap = coll.Maps["heap_allocs"]
	t.callsiteMap = coll.Maps["heap_callsite_live"]
	t.stacksMap = coll.Maps["heap_stacks"]
	if t.allocsMap == nil || t.callsiteMap == nil || t.stacksMap == nil {
		t.Close()
		return nil, errors.New("heap maps missing")
	}

	ex, err := link.OpenExecutable(libcPath)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("open libc %s: %w", libcPath, err)
	}

	// Scope the uprobes to the target process so siblings sharing libc don't
	// fire them; the in-kernel pid-namespace filter is defense-in-depth.
	opts := &link.UprobeOptions{PID: pid}
	probes := []struct {
		sym, prog string
		ret       bool
	}{
		{"malloc", "uprobe_malloc", false},
		{"malloc", "uretprobe_malloc", true},
		{"calloc", "uprobe_calloc", false},
		{"calloc", "uretprobe_calloc", true},
		{"realloc", "uprobe_realloc", false},
		{"realloc", "uretprobe_realloc", true},
		{"free", "uprobe_free", false},
	}
	var mallocEntry, mallocRet bool
	for _, p := range probes {
		prog := coll.Programs[p.prog]
		if prog == nil {
			t.Close()
			return nil, fmt.Errorf("program %s missing", p.prog)
		}
		var l link.Link
		if p.ret {
			l, err = ex.Uretprobe(p.sym, prog, opts)
		} else {
			l, err = ex.Uprobe(p.sym, prog, opts)
		}
		if err != nil {
			// Tolerate a missing symbol (rare for libc); malloc is required.
			fmt.Fprintf(os.Stderr, "warning: heap uprobe %s (%s): %v\n", p.sym, p.prog, err)
			continue
		}
		t.links = append(t.links, l)
		if p.sym == "malloc" {
			if p.ret {
				mallocRet = true
			} else {
				mallocEntry = true
			}
		}
	}
	if !mallocEntry || !mallocRet {
		t.Close()
		return nil, fmt.Errorf("could not attach malloc uprobes on %s", libcPath)
	}

	eventsMap := coll.Maps["heap_events"]
	if eventsMap == nil {
		t.Close()
		return nil, errors.New("heap_events ringbuf missing")
	}
	rb, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}
	t.rb = rb

	return t, nil
}

// Next blocks until the next heap event arrives. Returns io.EOF when the
// tracer is closed.
func (t *HeapTracer) Next() (HeapEvent, error) {
	var ev HeapEvent
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
	if len(rec.RawSample) < 48 {
		return ev, fmt.Errorf("short event: %d bytes", len(rec.RawSample))
	}
	if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
		return ev, fmt.Errorf("decode event: %w", err)
	}
	return ev, nil
}

// LiveCallSites snapshots heap_callsite_live: stack_id → running aggregate.
func (t *HeapTracer) LiveCallSites() (map[int32]HeapCallSiteRaw, error) {
	if t == nil || t.callsiteMap == nil {
		return nil, errors.New("tracer not initialized")
	}
	out := make(map[int32]HeapCallSiteRaw, 64)
	var k int32
	var v HeapCallSiteRaw
	iter := t.callsiteMap.Iterate()
	for iter.Next(&k, &v) {
		out[k] = v
	}
	return out, iter.Err()
}

// LeakScan walks heap_allocs and returns every live allocation whose age
// exceeds thresholdNs. Bounded by maxLeakScan to cap the work per tick.
func (t *HeapTracer) LeakScan(thresholdNs uint64) ([]HeapLeak, error) {
	if t == nil || t.allocsMap == nil {
		return nil, errors.New("tracer not initialized")
	}
	now, err := monotonicNs()
	if err != nil {
		return nil, err
	}
	var leaks []HeapLeak
	var ptr uint64
	var ai allocInfo
	iter := t.allocsMap.Iterate()
	scanned := 0
	for iter.Next(&ptr, &ai) {
		scanned++
		if scanned > maxLeakScan {
			break
		}
		if now < ai.TsNs {
			continue
		}
		age := now - ai.TsNs
		if age > thresholdNs {
			leaks = append(leaks, HeapLeak{Size: ai.Size, StackID: ai.StackID, AgeNs: age})
		}
	}
	return leaks, iter.Err()
}

// ResolveStack returns the user-stack frames captured for stackID (leaf first),
// trailing zero slots trimmed. A negative id (capture failed) yields nil.
func (t *HeapTracer) ResolveStack(stackID int32) ([]uint64, error) {
	if stackID < 0 {
		return nil, nil
	}
	if t == nil || t.stacksMap == nil {
		return nil, errors.New("tracer not initialized")
	}
	var frames [heapStackDepth]uint64
	if err := t.stacksMap.Lookup(uint32(stackID), &frames); err != nil {
		return nil, err
	}
	n := len(frames)
	for n > 0 && frames[n-1] == 0 {
		n--
	}
	return frames[:n], nil
}

// LibcRange returns the target VA range of the mapped libc, used to skip libc
// frames when picking the application call site.
func (t *HeapTracer) LibcRange() (lo, hi uint64) {
	if t == nil {
		return 0, 0
	}
	return t.libcLo, t.libcHi
}

func (t *HeapTracer) Close() error {
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
		t.allocsMap = nil
		t.callsiteMap = nil
		t.stacksMap = nil
	}
	return nil
}

// monotonicNs reads CLOCK_MONOTONIC in nanoseconds — the same clock
// bpf_ktime_get_ns() stamps allocations with, so ages compare directly.
func monotonicNs() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec), nil
}

// resolveLibc finds the libc mapped into pid and returns the file path to
// attach uprobes against plus the [lo,hi) virtual address range of its
// mappings. Returns an error when no libc is mapped (static / Go binaries) —
// the caller then leaves the heap collector inactive.
func resolveLibc(pid int) (path string, lo, hi uint64, err error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return "", 0, 0, fmt.Errorf("open maps of %d: %w", pid, err)
	}
	defer f.Close()

	var libcPath string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		// Format: "<lo>-<hi> perms offset dev inode   pathname"
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		p := strings.Join(fields[5:], " ")
		if !isLibc(filepath.Base(p)) {
			continue
		}
		if libcPath == "" {
			libcPath = p
		} else if p != libcPath {
			continue // a different libc-ish file; stick with the first
		}
		dash := strings.IndexByte(fields[0], '-')
		if dash < 0 {
			continue
		}
		start, e1 := strconv.ParseUint(fields[0][:dash], 16, 64)
		end, e2 := strconv.ParseUint(fields[0][dash+1:], 16, 64)
		if e1 != nil || e2 != nil {
			continue
		}
		if lo == 0 || start < lo {
			lo = start
		}
		if end > hi {
			hi = end
		}
	}
	if err := sc.Err(); err != nil {
		return "", 0, 0, err
	}
	if libcPath == "" {
		return "", 0, 0, errors.New("no libc mapped (static or non-libc binary)")
	}

	// Prefer the file as seen from the target's mount namespace so the symbol
	// offsets match the running libc exactly; fall back to the bare path.
	rooted := fmt.Sprintf("/proc/%d/root%s", pid, libcPath)
	if _, e := os.Stat(rooted); e == nil {
		return rooted, lo, hi, nil
	}
	return libcPath, lo, hi, nil
}

// isLibc matches the basename of a glibc or musl C library mapping.
func isLibc(base string) bool {
	return strings.HasPrefix(base, "libc.so") ||
		strings.HasPrefix(base, "libc-") ||
		strings.Contains(base, "musl")
}
