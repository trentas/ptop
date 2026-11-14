package report

import (
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/trentas/ptop/pkg/collector"
	pb "github.com/trentas/ptop/pkg/streampb"
)

// t0 is an arbitrary origin; readings land at t0 + i seconds.
var t0 = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

func at(sec float64) int64 { return t0.Add(time.Duration(sec * float64(time.Second))).UnixNano() }

func ev(sec float64, payload any) *pb.Event {
	e := &pb.Event{TsUnixNano: at(sec)}
	switch p := payload.(type) {
	case *pb.CpuSample:
		e.Payload = &pb.Event_Cpu{Cpu: p}
	case *pb.CpuProfile:
		e.Payload = &pb.Event_CpuProfile{CpuProfile: p}
	case *pb.SyscallSnapshot:
		e.Payload = &pb.Event_Syscalls{Syscalls: p}
	case *pb.HeapSnapshot:
		e.Payload = &pb.Event_Heap{Heap: p}
	case *pb.IoSnapshot:
		e.Payload = &pb.Event_Io{Io: p}
	case *pb.NetThroughputSample:
		e.Payload = &pb.Event_NetThroughput{NetThroughput: p}
	case *pb.NetworkSnapshot:
		e.Payload = &pb.Event_Network{Network: p}
	case *pb.NetErrorEvent:
		e.Payload = &pb.Event_NetError{NetError: p}
	case *pb.LockSnapshot:
		e.Payload = &pb.Event_Locks{Locks: p}
	case *pb.ThreadSnapshot:
		e.Payload = &pb.Event_Threads{Threads: p}
	case *pb.RunqLatency:
		e.Payload = &pb.Event_RunqLatency{RunqLatency: p}
	case *pb.SignalEvent:
		e.Payload = &pb.Event_Signal{Signal: p}
	case *pb.FSEvent:
		e.Payload = &pb.Event_FsEvent{FsEvent: p}
	case *pb.MemStats:
		e.Payload = &pb.Event_Memory{Memory: p}
	case *pb.HostSample:
		e.Payload = &pb.Event_Host{Host: p}
	case *pb.ProbeInfo:
		e.Payload = &pb.Event_ProbeChange{ProbeChange: p}
	default:
		panic("ev: unhandled payload type")
	}
	return e
}

func build(t *testing.T, cfg Config, target *pb.TargetInfo, events ...*pb.Event) *pb.CaptureReport {
	t.Helper()
	b := New(cfg)
	for _, e := range events {
		b.Emit(e)
	}
	return b.Report(target, Window{Start: t0, End: t0.Add(10 * time.Second), Requested: 10 * time.Second, How: pb.WindowEnd_WINDOW_END_COMPLETE})
}

func probes(active ...string) *pb.TargetInfo {
	ti := &pb.TargetInfo{Mode: pb.TargetMode_TARGET_MODE_PID, Pid: 42}
	for _, name := range active {
		ti.Probes = append(ti.Probes, &pb.ProbeInfo{Name: name, State: pb.ProbeState_PROBE_STATE_ACTIVE, Source: "eBPF"})
	}
	return ti
}

func TestDistributionIsNearestRank(t *testing.T) {
	var s series
	for _, v := range []float64{3, 1, 2, 5, 4} {
		s.add(v)
	}
	want := &pb.Distribution{N: 5, Min: 1, Mean: 3, P50: 3, P95: 5, Max: 5, First: 3, Last: 4}
	if got := s.dist(); !proto.Equal(got, want) {
		t.Errorf("dist = %v, want %v", got, want)
	}
	if (series{}).dist() != nil {
		t.Error("no readings must be no distribution, not one of zeros")
	}
}

// The window's first reading is the baseline: what a counter held when the
// report started is not the report's, and a syscall first seen later started
// at zero.
func TestSyscallsAreTheDifferenceFromTheBaseline(t *testing.T) {
	lat := func(v uint64) *uint64 { return &v }
	r := build(t, Config{TopN: 2}, probes(),
		ev(0, &pb.SyscallSnapshot{Stats: []*pb.SyscallStat{{Name: "read", Count: 100, LatencyNs: lat(1000)}}}),
		ev(1, &pb.SyscallSnapshot{Stats: []*pb.SyscallStat{
			{Name: "read", Count: 150, LatencyNs: lat(1600)},
			{Name: "write", Count: 10, LatencyNs: lat(50)},
		}}),
		ev(2, &pb.SyscallSnapshot{Stats: []*pb.SyscallStat{
			{Name: "read", Count: 200, LatencyNs: lat(2000)},
			{Name: "write", Count: 30, LatencyNs: lat(300)},
			{Name: "openat", Count: 5, LatencyNs: lat(10000)},
		}}),
	).GetSyscalls()

	if r.GetReadings() != 3 || r.GetSpanMs() != 2000 {
		t.Errorf("readings %d span %dms, want 3 and 2000", r.GetReadings(), r.GetSpanMs())
	}
	// Ranked by time: openat 10000ns, read 1000ns, then write 300ns cut.
	got := r.GetSyscalls()
	if len(got) != 2 || got[0].GetName() != "openat" || got[1].GetName() != "read" {
		t.Fatalf("syscalls = %v, want openat then read", got)
	}
	if got[1].GetCount() != 100 || got[1].GetLatencyNs() != 1000 {
		t.Errorf("read = %d calls %dns, want 100 and 1000 (200-100, 2000-1000)", got[1].GetCount(), got[1].GetLatencyNs())
	}
	if r.GetOmittedCount() != 30 || r.GetOmittedLatencyNs() != 300 {
		t.Errorf("omitted = %d calls %dns, want write's 30 and 300", r.GetOmittedCount(), r.GetOmittedLatencyNs())
	}
	if r.GetCount() != 135 || r.GetLatencyNs() != 11300 || r.GetTotalSyscalls() != 3 {
		t.Errorf("totals = %d calls %dns over %d syscalls, want 135, 11300, 3", r.GetCount(), r.GetLatencyNs(), r.GetTotalSyscalls())
	}
}

// A kernel entry evicted and recreated reads lower than before. The high-water
// mark keeps the difference from going negative or counting a stretch twice.
func TestACounterThatGoesBackwardsKeepsItsHighWaterMark(t *testing.T) {
	r := build(t, Config{}, probes(),
		ev(0, &pb.SyscallSnapshot{Stats: []*pb.SyscallStat{{Name: "read", Count: 10}}}),
		ev(1, &pb.SyscallSnapshot{Stats: []*pb.SyscallStat{{Name: "read", Count: 50}}}),
		ev(2, &pb.SyscallSnapshot{Stats: []*pb.SyscallStat{{Name: "read", Count: 3}}}),
	).GetSyscalls()
	if got := r.GetSyscalls()[0].GetCount(); got != 40 {
		t.Errorf("read = %d, want 40", got)
	}
	if r.LatencyNs != nil {
		t.Error("no reading was timed, so the latency must be absent, not 0")
	}
}

// One reading is a baseline and no interval: the section says so with its
// readings and span, and has nothing to list.
func TestOneReadingHasNoInterval(t *testing.T) {
	r := build(t, Config{}, probes(),
		ev(0, &pb.SyscallSnapshot{Stats: []*pb.SyscallStat{{Name: "read", Count: 10}}}),
	).GetSyscalls()
	if r.GetReadings() != 1 || r.GetSpanMs() != 0 || r.GetCount() != 0 || len(r.GetSyscalls()) != 0 {
		t.Errorf("got %v, want one reading, no span, nothing listed", r)
	}
}

func TestCpuProfileSumsWindowsAfterTheFirstByFunction(t *testing.T) {
	site := func(fn string, addr, samples uint64) *pb.CpuSite {
		return &pb.CpuSite{Func: fn, Module: "app", Addr: addr, Samples: samples, StackId: addr}
	}
	r := build(t, Config{TopN: 1}, probes(),
		// The baseline: its window began before the report, so none of it counts.
		ev(1, &pb.CpuProfile{TotalSamples: 1000, Sites: []*pb.CpuSite{site("hot", 1, 1000)}, WindowMs: 1000, SampleRateHz: 99}),
		// "hot" at two addresses in two windows: one function.
		ev(2, &pb.CpuProfile{TotalSamples: 100, UnresolvedSamples: 5, KernelModeSamples: 10, WindowMs: 1000, SampleRateHz: 90,
			RequestedRateHz: 99, TotalSites: 3, Sites: []*pb.CpuSite{site("hot", 1, 60), site("warm", 2, 30)}}),
		ev(3, &pb.CpuProfile{TotalSamples: 100, WindowMs: 1000, SampleRateHz: 100, RequestedRateHz: 99, TotalSites: 2,
			Sites: []*pb.CpuSite{site("hot", 7, 70), site("warm", 2, 30)}}),
	).GetCpuProfile()

	if r.GetReadings() != 3 || r.GetSpanMs() != 2000 || r.GetTotalSamples() != 200 {
		t.Errorf("readings %d span %dms total %d, want 3, 2000, 200", r.GetReadings(), r.GetSpanMs(), r.GetTotalSamples())
	}
	if len(r.GetSites()) != 1 {
		t.Fatalf("sites = %v, want only hot", r.GetSites())
	}
	hot := r.GetSites()[0]
	if hot.GetFunc() != "hot" || hot.GetSamples() != 130 || hot.GetSharePct() != 65 {
		t.Errorf("hot = %d samples, %.0f%%, want 130 and 65", hot.GetSamples(), hot.GetSharePct())
	}
	// Its address and stack are the window where it took the most samples.
	if hot.GetAddr() != 7 || hot.GetStackId() != 7 {
		t.Errorf("hot is named by addr %d stack %d, want the 70-sample window's 7", hot.GetAddr(), hot.GetStackId())
	}
	// 200 total, 5 unresolved, 130 listed: 65 omitted. That covers warm's 60
	// and the 5 samples the first window's own list had already cut.
	if r.GetOmittedSamples() != 65 || r.GetTotalSites() != 2 || r.GetTruncatedReadings() != 1 {
		t.Errorf("omitted %d over %d sites, %d truncated, want 65, 2, 1", r.GetOmittedSamples(), r.GetTotalSites(), r.GetTruncatedReadings())
	}
	if r.GetSampleRateHz() != 95 || r.GetRequestedRateHz() != 99 {
		t.Errorf("rate %.1f of %.1f, want the window-weighted 95 of 99", r.GetSampleRateHz(), r.GetRequestedRateHz())
	}
}

func TestHeapGoLane(t *testing.T) {
	site := func(cs, count, bytes uint64) *pb.HeapCallSite {
		return &pb.HeapCallSite{CallSite: cs, AddrHex: "0x" + string(rune('0'+cs)), AllocCount: count, AllocBytes: bytes}
	}
	r := build(t, Config{TopN: 1}, probes(),
		ev(0, &pb.HeapSnapshot{Lane: collector.HeapLaneGo, AllocRate: 1e6, AllocBytesRate: 1e9, TotalCallSites: 2,
			TopCallSites: []*pb.HeapCallSite{site(1, 100, 1000), site(2, 10, 100)}}),
		// 1000 allocations/s and 64 KiB/s over half a second, then over a second.
		ev(0.5, &pb.HeapSnapshot{Lane: collector.HeapLaneGo, AllocRate: 1000, AllocBytesRate: 65536, TotalCallSites: 3,
			OmittedAllocCount: 7, OmittedAllocBytes: 70,
			TopCallSites: []*pb.HeapCallSite{site(1, 400, 4000), site(2, 20, 300)}}),
		ev(1.5, &pb.HeapSnapshot{Lane: collector.HeapLaneGo, AllocRate: 1000, AllocBytesRate: 65536, TotalCallSites: 3,
			OmittedAllocCount: 7, OmittedAllocBytes: 70,
			TopCallSites: []*pb.HeapCallSite{site(1, 900, 9000), site(2, 30, 500)}}),
	).GetHeap()

	if r.GetAllocCount() != 1500 || r.GetAllocBytes() != 98304 {
		t.Errorf("totals %d allocations %d bytes, want 1500 and 98304: each rate times its interval, the baseline's left out",
			r.GetAllocCount(), r.GetAllocBytes())
	}
	if len(r.GetSites()) != 1 || r.GetSites()[0].GetAllocBytes() != 8000 || r.GetSites()[0].GetAllocCount() != 800 {
		t.Fatalf("sites = %v, want site 1 at 800 allocations, 8000 bytes", r.GetSites())
	}
	// Site 2 grew by 400 bytes in 20 allocations, and a third site the
	// collector cut from both later readings allocated 70 in 7.
	if r.GetOmittedAllocBytes() != 470 || r.GetOmittedAllocCount() != 27 {
		t.Errorf("omitted %d allocations %d bytes, want 27 and 470", r.GetOmittedAllocCount(), r.GetOmittedAllocBytes())
	}
	// The third site was never listed, so the census stops at two, and the two
	// truncated readings are what say it is not a census.
	if r.GetTotalCallSites() != 2 || r.GetTruncatedReadings() != 2 {
		t.Errorf("%d sites, %d truncated readings, want 2 and 2", r.GetTotalCallSites(), r.GetTruncatedReadings())
	}
	if r.GetLiveHeapBytes() != nil {
		t.Error("the Go lane measures no live bytes: their distribution must be absent")
	}
}

// The libc lane keeps the live set per site, so its list is the last
// reading's, re-cut, with that reading's own omitted totals carried along.
func TestHeapLibcLaneListsTheLastLiveSet(t *testing.T) {
	r := build(t, Config{TopN: 1}, probes(),
		ev(0, &pb.HeapSnapshot{Lane: collector.HeapLaneLibc, LiveMeasured: true, LiveHeapBytes: 10,
			TopCallSites: []*pb.HeapCallSite{{CallSite: 9, AddrHex: "0x9", LiveBytes: 10}}}),
		ev(1, &pb.HeapSnapshot{Lane: collector.HeapLaneLibc, LiveMeasured: true, LiveHeapBytes: 600, TotalCallSites: 3,
			OmittedAllocCount: 1, OmittedLiveBytes: 100,
			TopCallSites: []*pb.HeapCallSite{
				{CallSite: 1, AddrHex: "0x1", LiveBytes: 200, AllocCount: 2},
				{CallSite: 2, AddrHex: "0x2", LiveBytes: 300, AllocCount: 3},
			}}),
	).GetHeap()
	if len(r.GetSites()) != 1 || r.GetSites()[0].GetCallSite() != 2 {
		t.Fatalf("sites = %v, want 0x2, the larger live set", r.GetSites())
	}
	if r.GetTotalCallSites() != 3 || r.GetOmittedLiveBytes() != 300 || r.GetOmittedAllocCount() != 3 {
		t.Errorf("%d sites, omitted %d live bytes %d allocations, want 3, 300, 3", r.GetTotalCallSites(), r.GetOmittedLiveBytes(), r.GetOmittedAllocCount())
	}
	if d := r.GetLiveHeapBytes(); d.GetN() != 2 || d.GetLast() != 600 {
		t.Errorf("live heap = %v, want two readings ending at 600", d)
	}
}

func TestIoFilesAndBuckets(t *testing.T) {
	buckets := func(r, w float64) []*pb.LatencyBucket {
		return []*pb.LatencyBucket{{Label: "<0.1ms", Read: r, Write: w}, {Label: ">20ms", Read: 1, Write: 0}}
	}
	r := build(t, Config{TopN: 1}, probes(collector.SubsystemIO),
		ev(0, &pb.IoSnapshot{LatencyBuckets: buckets(500, 500), TopFiles: []*pb.IoFileStats{
			{Path: "/a", Type: "log", Writes: 10, Bytes: 100, LatencyMs: 0.01},
		}}),
		ev(0.5, &pb.IoSnapshot{LatencyBuckets: buckets(3, 4), TopFiles: []*pb.IoFileStats{
			{Path: "/a", Type: "log", Writes: 110, Bytes: 1100, LatencyMs: 0.01},
			{Path: "/b", Type: "db", Reads: 2, Bytes: 8192, LatencyMs: 25},
		}}),
		ev(1, &pb.IoSnapshot{LatencyBuckets: buckets(5, 6), TopFiles: []*pb.IoFileStats{
			{Path: "/a", Type: "log", Writes: 210, Bytes: 2100, LatencyMs: 0.01},
			{Path: "/b", Type: "db", Reads: 2, Bytes: 8192, LatencyMs: 25},
		}}),
	).GetIo()

	// /b's two reads took 50ms; /a's 200 writes took 2ms. Time ranks /b first.
	if len(r.GetFiles()) != 1 || r.GetFiles()[0].GetPath() != "/b" || r.GetFiles()[0].GetLatencyNs() != 50_000_000 {
		t.Fatalf("files = %v, want /b at 50ms", r.GetFiles())
	}
	// /a at the baseline held 10 writes and 0.1ms; it gained 200 writes.
	if r.GetOmittedWrites() != 200 || r.GetOmittedBytes() != 2000 || r.GetOmittedLatencyNs() != 2_000_000 {
		t.Errorf("omitted %d writes %d bytes %dns, want 200, 2000, 2ms", r.GetOmittedWrites(), r.GetOmittedBytes(), r.GetOmittedLatencyNs())
	}
	b := r.GetLatencyBuckets()
	if len(b) != 2 || b[0].GetRead() != 8 || b[0].GetWrite() != 10 || b[1].GetRead() != 2 {
		t.Errorf("buckets = %v, want the windows after the baseline summed: 8/10 and 2/0", b)
	}
	if fs := r.GetFs(); fs == nil || fs.GetTotal() != 0 {
		t.Errorf("fs = %v: with the io probe on eBPF, no event is a measured zero", fs)
	}
}

func TestNetwork(t *testing.T) {
	conn := func(remote string, fd int32, tx, rx uint64) *pb.NetConn {
		return &pb.NetConn{Type: "TCP", Remote: remote, Fd: fd, State: "ESTABLISHED", TxBytes: tx, RxBytes: rx}
	}
	events := []*pb.Event{
		ev(0, &pb.NetThroughputSample{TxBytes: 1000, RxBytes: 2000}),
		ev(1, &pb.NetThroughputSample{TxBytes: 1500, RxBytes: 2600, DroppedConnections: 1}),
		ev(0, &pb.NetworkSnapshot{Conns: []*pb.NetConn{conn("10.0.0.1:443", 5, 1000, 2000)}}),
		ev(1, &pb.NetworkSnapshot{Conns: []*pb.NetConn{conn("10.0.0.1:443", 5, 1100, 2100), conn("10.0.0.2:80", 6, 400, 500)}}),
		ev(0.5, &pb.NetErrorEvent{Kind: "reset", Remote: "10.0.0.3:80"}),
		ev(0.6, &pb.NetErrorEvent{Kind: "reset", Remote: "10.0.0.3:80"}),
	}
	r := build(t, Config{TopN: 1}, probes(collector.SubsystemNetwork), events...).GetNetwork()
	if r.GetTxBytes() != 500 || r.GetRxBytes() != 600 || r.GetDroppedConnections() != 1 {
		t.Errorf("volume %d/%d dropped %d, want 500/600 and 1", r.GetTxBytes(), r.GetRxBytes(), r.GetDroppedConnections())
	}
	// The new connection moved 900 bytes, all of it in the window; the old one
	// moved 200 after the baseline.
	if len(r.GetConns()) != 1 || r.GetConns()[0].GetRemote() != "10.0.0.2:80" || r.GetConns()[0].GetTxBytes() != 400 {
		t.Fatalf("conns = %v, want 10.0.0.2:80 with 400 sent", r.GetConns())
	}
	if r.GetOmittedTxBytes() != 100 || r.GetOmittedRxBytes() != 100 || r.GetTotalConns() != 2 {
		t.Errorf("omitted %d/%d of %d conns, want 100/100 of 2", r.GetOmittedTxBytes(), r.GetOmittedRxBytes(), r.GetTotalConns())
	}
	if r.Errors == nil || r.GetErrors() != 2 || r.GetErrorCounts()[0].GetCount() != 2 {
		t.Errorf("errors = %v %v, want 2, both resets from one peer", r.Errors, r.GetErrorCounts())
	}

	// Without the eBPF lane nothing counts errors: absent, not zero.
	proc := &pb.TargetInfo{Probes: []*pb.ProbeInfo{{Name: collector.SubsystemNetwork, State: pb.ProbeState_PROBE_STATE_ACTIVE, Source: "/proc"}}}
	if got := build(t, Config{}, proc, events[:4]...).GetNetwork(); got.Errors != nil {
		t.Errorf("errors = %d from a /proc lane, want absent", got.GetErrors())
	}
}

func TestLocksRankByWaitTime(t *testing.T) {
	lock := func(uaddr, waits uint64, meanMs float64) *pb.LockEntry {
		return &pb.LockEntry{Uaddr: uaddr, Waiters: waits, LatencyMs: meanMs}
	}
	r := build(t, Config{TopN: 1, ListCap: 2}, probes(),
		ev(0, &pb.LockSnapshot{Locks: []*pb.LockEntry{lock(1, 10, 1)}}),
		// Lock 2 is waited on less often, for longer: 5 waits × 10ms against
		// lock 1's 90 waits gaining 8ms of total wait.
		ev(1, &pb.LockSnapshot{Locks: []*pb.LockEntry{lock(1, 100, 0.18), lock(2, 5, 10)}}),
	).GetLocks()
	if len(r.GetLocks()) != 1 || r.GetLocks()[0].GetUaddr() != 2 || r.GetLocks()[0].GetWaitNs() != 50_000_000 {
		t.Fatalf("locks = %v, want lock 2 at 50ms", r.GetLocks())
	}
	if r.GetOmittedWaits() != 90 || r.GetOmittedWaitNs() != 8_000_000 {
		t.Errorf("omitted %d waits %dns, want 90 and 8ms", r.GetOmittedWaits(), r.GetOmittedWaitNs())
	}
	if r.GetWaits() != 95 || r.GetTotalLocks() != 2 || r.GetTruncatedReadings() != 1 {
		t.Errorf("%d waits on %d locks, %d truncated, want 95, 2 and 1 (the reading as long as the cap)",
			r.GetWaits(), r.GetTotalLocks(), r.GetTruncatedReadings())
	}
}

func TestThreadsRankByOnCpuTime(t *testing.T) {
	r := build(t, Config{TopN: 1}, probes(),
		ev(0, &pb.ThreadSnapshot{Threads: []*pb.ThreadInfo{
			{Tid: 1, Name: "main", CpuPct: 40, OffCpuPct: 60},
			{Tid: 2, Name: "worker", CpuPct: 90, RunqWaitPct: 10, CtxSwitches: 3},
		}}),
		ev(1, &pb.ThreadSnapshot{Threads: []*pb.ThreadInfo{
			{Tid: 1, Name: "main", CpuPct: 60, OffCpuPct: 40, State: "sleeping"},
		}}),
		ev(1, &pb.RunqLatency{Count: 10, SumNs: 100, Buckets: []uint64{10}}),
		ev(2, &pb.RunqLatency{Count: 15, SumNs: 400, Buckets: []uint64{12, 3}}),
	).GetThreads()
	// main spent 100 points of CPU over the window, worker 90 in the one
	// reading it lived for: main ranks first, worker is the omitted 45%.
	th := r.GetThreads()
	if len(th) != 1 || th[0].GetTid() != 1 || th[0].GetCpuPct() != 50 || th[0].GetOffCpuPct() != 50 || th[0].GetState() != "sleeping" {
		t.Fatalf("threads = %v, want main at a mean 50%% on and off CPU, sleeping", th)
	}
	if r.GetOmittedCpuPct() != 45 || r.GetTotalThreads() != 2 || r.GetCount().GetMax() != 2 {
		t.Errorf("omitted %.0f%% of %d threads, max %v, want 45%% of 2 and 2", r.GetOmittedCpuPct(), r.GetTotalThreads(), r.GetCount().GetMax())
	}
	rq := r.GetRunqLatency()
	if rq.GetCount() != 5 || rq.GetSumNs() != 300 || len(rq.GetBuckets()) != 2 || rq.GetBuckets()[0] != 2 || rq.GetBuckets()[1] != 3 {
		t.Errorf("runq = %v, want 5 waits, 300ns, buckets 2 and 3", rq)
	}
}

// An event section is present whenever its probe ran on eBPF, so its zeros are
// measurements, and absent when nothing could have counted.
func TestEventSectionsArePresentWhenTheirProbeRan(t *testing.T) {
	quiet := build(t, Config{}, probes(collector.SubsystemSignals, collector.SubsystemLifecycle, collector.SubsystemSecurity))
	if quiet.GetSignals() == nil || quiet.GetLifecycle() == nil || quiet.GetSecurity() == nil {
		t.Errorf("with their probes active, an idle target's event sections must read zero: %v", quiet)
	}
	none := build(t, Config{}, probes())
	if none.GetSignals() != nil || none.GetLifecycle() != nil || none.GetSecurity() != nil || none.GetIo() != nil || none.GetNetwork() != nil {
		t.Errorf("with no probe to count them, the event sections must be absent: %v", none)
	}

	r := build(t, Config{TopN: 1}, probes(collector.SubsystemSignals),
		ev(0, &pb.SignalEvent{Signal: "SIGURG", SenderComm: "app"}),
		ev(0, &pb.SignalEvent{Signal: "SIGURG", SenderComm: "app"}),
		ev(0, &pb.SignalEvent{Signal: "SIGTERM", SenderComm: "systemd"}),
	).GetSignals()
	if r.GetTotal() != 3 || len(r.GetSignals()) != 1 || r.GetSignals()[0].GetCount() != 2 || r.GetOmitted() != 1 {
		t.Errorf("signals = %v, want 3 with SIGURG×2 listed and 1 omitted", r)
	}
}

func TestWindowAndProbeChanges(t *testing.T) {
	detached := &pb.ProbeInfo{Name: "heap", State: pb.ProbeState_PROBE_STATE_DISABLED, Detail: "over budget"}
	r := build(t, Config{TopN: 7}, probes(), ev(3, detached), ev(1, &pb.CpuSample{UsagePct: 12}))
	w := r.GetWindow()
	if w.GetDurationMs() != 10000 || w.GetRequestedMs() != 10000 || w.GetTopN() != 7 || w.GetEnd() != pb.WindowEnd_WINDOW_END_COMPLETE {
		t.Errorf("window = %v", w)
	}
	if len(r.GetProbeChanges()) != 1 || r.GetProbeChanges()[0].GetTsUnixNano() != at(3) || !proto.Equal(r.GetProbeChanges()[0].GetProbe(), detached) {
		t.Errorf("probe changes = %v, want the detach at t+3s", r.GetProbeChanges())
	}
	if r.GetCpu().GetUsagePct().GetMean() != 12 {
		t.Errorf("cpu = %v", r.GetCpu())
	}
	// Axes that sent nothing are absent.
	if r.GetSyscalls() != nil || r.GetHeap() != nil || r.GetThreads() != nil || r.GetMemory() != nil || r.GetHost() != nil {
		t.Errorf("sections with no readings must be absent: %v", r)
	}
}

func TestHostSaturationOverTheSpan(t *testing.T) {
	sample := func(steal *float64, throttled uint64, some uint64) *pb.HostSample {
		return &pb.HostSample{
			StealPct:   steal,
			Throttling: &pb.CpuThrottling{NrPeriods: throttled * 2, NrThrottled: throttled, ThrottledUsec: throttled * 100},
			Pressure:   &pb.CgroupPressure{Cpu: &pb.Pressure{Some: &pb.PressureStall{TotalUsec: some}}},
			Limits:     &pb.CgroupLimits{CpuMax: "max 100000"},
		}
	}
	r := build(t, Config{}, probes(),
		ev(0, sample(nil, 10, 1000)),
		ev(1, sample(proto.Float64(2), 15, 4000)),
	).GetHost()
	if r.GetThrottling().GetNrThrottled() != 5 || r.GetThrottling().GetThrottledUsec() != 500 {
		t.Errorf("throttling = %v, want 5 periods and 500µs", r.GetThrottling())
	}
	if p := r.GetPressure().GetCpu(); p.GetSomeUsec() != 3000 || p.FullUsec != nil {
		t.Errorf("cpu pressure = %v, want 3000µs some and no full line", p)
	}
	if r.GetPressure().GetMemory() != nil || r.GetStealPct().GetN() != 1 || r.GetLimits().GetCpuMax() != "max 100000" {
		t.Errorf("host = %v", r)
	}
}

func TestMemory(t *testing.T) {
	r := build(t, Config{}, probes(),
		ev(0, &pb.MemStats{RssBytes: 100, PageFaults: 1000}),
		ev(1, &pb.MemStats{RssBytes: 300, PageFaults: 1500}),
	).GetMemory()
	if r.GetPageFaults() != 500 || r.GetRssBytes().GetFirst() != 100 || r.GetRssBytes().GetLast() != 300 || r.GetSpanMs() != 1000 {
		t.Errorf("memory = %v", r)
	}
}

// Ties are broken by name, so two runs over the same events print the same
// report whatever order a map was walked in.
func TestReportIsDeterministic(t *testing.T) {
	events := []*pb.Event{
		ev(0, &pb.FSEvent{Op: "deleted", Path: "/b"}),
		ev(0, &pb.FSEvent{Op: "deleted", Path: "/a"}),
		ev(0, &pb.FSEvent{Op: "deleted", Path: "/c"}),
	}
	first, _ := protojson.Marshal(build(t, Config{TopN: 2}, probes(collector.SubsystemIO), events...))
	for range 20 {
		again, _ := protojson.Marshal(build(t, Config{TopN: 2}, probes(collector.SubsystemIO), events...))
		if string(again) != string(first) {
			t.Fatalf("two builds differ:\n%s\n%s", first, again)
		}
	}
	fs := build(t, Config{TopN: 2}, probes(collector.SubsystemIO), events...).GetIo().GetFs()
	if fs.GetEvents()[0].GetPath() != "/a" || fs.GetEvents()[1].GetPath() != "/b" || fs.GetOmitted() != 1 || fs.GetDeleted() != 3 {
		t.Errorf("fs = %v, want /a and /b listed, /c omitted", fs)
	}
}

// Every list is bounded by the top-N, whatever the target did.
func TestListsAreCutToTopN(t *testing.T) {
	b := New(Config{TopN: 3})
	var stats []*pb.SyscallStat
	for i := range 100 {
		stats = append(stats, &pb.SyscallStat{Name: string(rune('a'+i%26)) + string(rune('a'+i/26)), Count: uint64(i + 1)})
	}
	b.Emit(ev(0, &pb.SyscallSnapshot{}))
	b.Emit(ev(1, &pb.SyscallSnapshot{Stats: stats}))
	for i := range 100 {
		b.Emit(ev(1, &pb.SignalEvent{Signal: string(rune('A' + i%26))}))
	}
	r := b.Report(probes(collector.SubsystemSignals), Window{Start: t0, End: t0.Add(time.Second)})
	if len(r.GetSyscalls().GetSyscalls()) != 3 || len(r.GetSignals().GetSignals()) != 3 {
		t.Errorf("lists of %d and %d, want 3", len(r.GetSyscalls().GetSyscalls()), len(r.GetSignals().GetSignals()))
	}
	if r.GetSyscalls().GetTotalSyscalls() != 100 || r.GetSignals().GetTotal() != 100 {
		t.Errorf("the totals must count everything, listed or not")
	}
}
