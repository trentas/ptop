//go:build linux && ebpf

package bpf

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/trentas/ptop/pkg/symbol"
)

// Where HotSpot begins and ends a stop-the-world (#189).
const (
	// SafepointSynchronize::begin() and ::end(), as libjvm.so's .symtab names
	// them. They are local symbols: .dynsym exports only the JNI and JVM_
	// entry points, so a libjvm.so stripped of .symtab has no safepoint lane.
	jvmSafepointBeginSymbol = "_ZN20SafepointSynchronize5beginEv"
	jvmSafepointEndSymbol   = "_ZN20SafepointSynchronize3endEv"

	// HotSpot's own collection boundaries, compiled in by --enable-dtrace.
	jvmUSDTProvider = "hotspot"
	jvmGCBeginProbe = "gc__begin"
	jvmGCEndProbe   = "gc__end"
)

// The lanes, as indexes into jvmpause_totals. Mirrors LANE_* in
// programs/jvmpause.bpf.c.
const (
	jvmLaneSafepoint = 0
	jvmLaneGC        = 1
)

// JVMPauseTracer times a HotSpot JVM's stop-the-world pauses (#189) in two
// lanes: every safepoint, and every collection. See programs/jvmpause.bpf.c.
// A lane that could not attach reads zero from Totals; Lanes says which did.
type JVMPauseTracer struct {
	coll   *ebpf.Collection
	totals *ebpf.Map
	links  []link.Link

	safepoints, gc bool
	caveat         string
}

// jvmSite is one place a lane's program goes: a file offset in libjvm.so, and
// the semaphore offset when the site is a guarded USDT probe.
type jvmSite struct {
	prog, name  string
	off, refCtr uint64
	isEnd       bool
}

// jvmLane is what one lane attaches, or why it cannot.
type jvmLane struct {
	sites []jvmSite
	why   string // non-empty when the lane cannot attach
}

// OpenJVMPauseTracer attaches to the target's libjvm.so. Returns ErrNotJVM when
// none is mapped: a JVM pause axis there is unsupported, never an empty one.
//
// It succeeds when at least one lane attached; the other, if any, is named in
// Caveat. A libjvm.so in which neither lane can be found (an OpenJ9 shim, a
// HotSpot stripped of its symbols and built without DTrace probes) is an error
// that says which of the two is missing.
func OpenJVMPauseTracer(pid int) (*JVMPauseTracer, error) {
	if pid <= 0 {
		return nil, errors.New("invalid pid")
	}
	path, err := resolveLibJVM(pid)
	if err != nil {
		return nil, err
	}
	lanes, err := planJVMLanes(path)
	if err != nil {
		return nil, err
	}
	if lanes[jvmLaneSafepoint].why != "" && lanes[jvmLaneGC].why != "" {
		return nil, fmt.Errorf("%s: %s; and %s", path, lanes[jvmLaneSafepoint].why, lanes[jvmLaneGC].why)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(jvmpauseBPFObj))
	if err != nil {
		return nil, fmt.Errorf("parse jvmpause BPF object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, kprobeLoadError("load jvmpause collection", err)
	}
	t := &JVMPauseTracer{coll: coll, totals: coll.Maps["jvmpause_totals"]}
	targetMap := coll.Maps["jvmpause_target_pid"]
	if targetMap == nil || t.totals == nil {
		t.Close()
		return nil, errors.New("jvmpause maps missing")
	}
	tf, err := resolveTarget(TargetPID(pid))
	if err != nil {
		t.Close()
		return nil, err
	}
	if err := writeTargetFilter(coll, targetMap, tf); err != nil {
		t.Close()
		return nil, fmt.Errorf("set jvmpause_target_pid: %w", err)
	}

	ex, err := link.OpenExecutable(path)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	for i := range lanes {
		if lanes[i].why != "" {
			continue
		}
		links, err := t.attachLane(ex, pid, lanes[i].sites)
		if err != nil {
			lanes[i].why = err.Error()
			continue
		}
		t.links = append(t.links, links...)
		switch i {
		case jvmLaneSafepoint:
			t.safepoints = true
		case jvmLaneGC:
			t.gc = true
		}
	}
	switch {
	case !t.safepoints && !t.gc:
		t.Close()
		return nil, fmt.Errorf("%s; and %s", lanes[jvmLaneSafepoint].why, lanes[jvmLaneGC].why)
	case !t.safepoints:
		t.caveat = "GC pauses only: " + lanes[jvmLaneSafepoint].why +
			", so the stops that were not collections are not timed"
	case !t.gc:
		t.caveat = "safepoints only: " + lanes[jvmLaneGC].why +
			", so which of them were collections is unknown"
	}
	return t, nil
}

// attachLane attaches every site of one lane, the ends before the begins: a
// begin attached first could open a pause whose end is not yet hooked, while an
// end with no begin is dropped by the program. A lane attaches whole or not at
// all — a probe hooked at some of its sites would under-count without saying
// so — so a failure detaches what the lane had attached.
func (t *JVMPauseTracer) attachLane(ex *link.Executable, pid int, sites []jvmSite) ([]link.Link, error) {
	var links []link.Link
	fail := func(err error) ([]link.Link, error) {
		for _, l := range links {
			_ = l.Close()
		}
		return nil, err
	}
	for _, pass := range []bool{true, false} {
		for _, s := range sites {
			if s.isEnd != pass {
				continue
			}
			prog := t.coll.Programs[s.prog]
			if prog == nil {
				return fail(fmt.Errorf("program %s missing", s.prog))
			}
			l, err := ex.Uprobe(s.name, prog, &link.UprobeOptions{PID: pid, Address: s.off, RefCtrOffset: s.refCtr})
			if err != nil {
				return fail(uprobeAttachError(fmt.Sprintf("attach uprobe %s at file offset %#x", s.name, s.off), err))
			}
			links = append(links, l)
		}
	}
	return links, nil
}

// planJVMLanes locates both lanes' sites in libjvm.so. A lane that is not there
// gets a reason, not an error: the other may still be.
func planJVMLanes(path string) ([2]jvmLane, error) {
	var lanes [2]jvmLane
	f, err := os.Open(path)
	if err != nil {
		return lanes, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	mod, err := symbol.OpenModule(f, path)
	if err != nil {
		return lanes, fmt.Errorf("parse %s: %w", path, err)
	}
	offOf := func(sym string) (uint64, bool) {
		vaddr, _, ok := mod.FuncStart(sym)
		if !ok {
			return 0, false
		}
		return mod.FileOffset(vaddr)
	}
	beginOff, okB := offOf(jvmSafepointBeginSymbol)
	endOff, okE := offOf(jvmSafepointEndSymbol)
	if okB && okE {
		lanes[jvmLaneSafepoint].sites = []jvmSite{
			{prog: "uprobe_jvm_safepoint_end", name: "SafepointSynchronize::end", off: endOff, isEnd: true},
			{prog: "uprobe_jvm_safepoint_begin", name: "SafepointSynchronize::begin", off: beginOff},
		}
	} else {
		lanes[jvmLaneSafepoint].why = "libjvm.so has no SafepointSynchronize::begin()/end() in a symbol table (stripped of .symtab)"
	}

	probes, err := symbol.ReadUSDTProbes(f)
	if err != nil {
		lanes[jvmLaneGC].why = fmt.Sprintf("libjvm.so's USDT notes do not parse: %v", err)
		return lanes, nil
	}
	var begins, ends int
	for _, p := range probes {
		if p.Provider != jvmUSDTProvider {
			continue
		}
		s := jvmSite{off: p.LocationOffset, refCtr: p.SemaphoreOffset}
		switch p.Name {
		case jvmGCBeginProbe:
			s.prog, s.name = "uprobe_jvm_gc_begin", "hotspot:gc__begin"
			begins++
		case jvmGCEndProbe:
			s.prog, s.name, s.isEnd = "uprobe_jvm_gc_end", "hotspot:gc__end", true
			ends++
		default:
			continue
		}
		lanes[jvmLaneGC].sites = append(lanes[jvmLaneGC].sites, s)
	}
	if begins == 0 || ends == 0 {
		lanes[jvmLaneGC].sites = nil
		lanes[jvmLaneGC].why = "libjvm.so carries no hotspot:gc__begin/gc__end probes (built without --enable-dtrace)"
	}
	return lanes, nil
}

// resolveLibJVM finds the libjvm.so mapped into pid and returns the path to
// attach against, preferring the target's mount-namespace view like
// resolveLibc. ErrNotJVM when none is mapped.
func resolveLibJVM(pid int) (string, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return "", targetReadError(fmt.Sprintf("open maps of %d", pid), err)
	}
	defer f.Close()

	var path string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		p := strings.Join(fields[5:], " ")
		if filepath.Base(strings.TrimSuffix(p, " (deleted)")) == "libjvm.so" {
			path = p
			break
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	if path == "" {
		return "", ErrNotJVM
	}
	if strings.HasSuffix(path, " (deleted)") {
		// A JDK upgraded under a running JVM: the file the probes would name
		// is not the one the process runs.
		return "", fmt.Errorf("%s was replaced on disk since the JVM mapped it", strings.TrimSuffix(path, " (deleted)"))
	}
	rooted := fmt.Sprintf("/proc/%d/root%s", pid, path)
	if _, e := os.Stat(rooted); e == nil {
		return rooted, nil
	}
	return path, nil
}

// Lanes reports which lanes attached.
func (t *JVMPauseTracer) Lanes() (safepoints, gc bool) {
	if t == nil {
		return false, false
	}
	return t.safepoints, t.gc
}

// Caveat names the lane that did not attach and why, or "".
func (t *JVMPauseTracer) Caveat() string {
	if t == nil {
		return ""
	}
	return t.caveat
}

// Totals reads both lanes' cumulative aggregates.
func (t *JVMPauseTracer) Totals() (safepoints, gc PauseTotals, err error) {
	if t == nil || t.totals == nil {
		return safepoints, gc, errors.New("tracer not initialized")
	}
	if err := t.totals.Lookup(uint32(jvmLaneSafepoint), &safepoints); err != nil {
		return safepoints, gc, fmt.Errorf("read jvmpause_totals[safepoint]: %w", err)
	}
	if err := t.totals.Lookup(uint32(jvmLaneGC), &gc); err != nil {
		return safepoints, gc, fmt.Errorf("read jvmpause_totals[gc]: %w", err)
	}
	return safepoints, gc, nil
}

// Close detaches the probes and releases the maps.
func (t *JVMPauseTracer) Close() error {
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
