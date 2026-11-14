// Package report builds the capture report of `ptop --for` (#156): one fixed
// window over one target, digested into a CaptureReport an agent can read
// whole.
//
// A Builder consumes the stream's own events, the ones a gRPC subscriber and
// the JSONL export receive, so every number in a report is one the stream
// carried too. It has the shape of a serve.Sink. Emit aggregates in place,
// so nothing queues and nothing is shed on the way in.
//
// The rules every section follows are documented on CaptureReport in
// proto/report.proto. The two that shape this code:
//
//   - A total is the difference between an axis's first reading in the window
//     and its last. The first reading is the baseline, so a counter that was
//     already running when the window opened is not credited to it.
//   - A per-window figure (a CPU profile, the io histogram) is summed over
//     every reading after the first. The first reading's window began before
//     the report did, and leaving it out makes those figures cover the same
//     span as the totals.
package report

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/trentas/ptop/pkg/collector"
	pb "github.com/trentas/ptop/pkg/streampb"
)

const (
	// DefaultTopN is how many entries a list carries unless asked otherwise.
	DefaultTopN = 10
	// MaxTopN bounds --top: past it a report stops fitting the context window
	// it exists for.
	MaxTopN = 50
	// CollectorListCap is the SetConfig.ListCap a capture runs its collectors
	// with. A report sums lists that each reading cuts, so a site cut from one
	// reading is missing from that reading's share of the sum. At 8, the
	// stream's cut, a busy target truncates most readings; past MaxTopN the
	// report keeps room for every site that could reach its own list.
	CollectorListCap = 64
)

// Config tunes a Builder.
type Config struct {
	// TopN is the most entries any list carries. 0 takes DefaultTopN.
	TopN int
	// ListCap is the collectors' SetConfig.ListCap: how many locks one reading
	// carries. The lock list says nothing of what it cut, so a reading that
	// long counts as truncated. 0 takes collector.DefaultListCap.
	ListCap int
}

// Window is when the capture ran, as the caller timed it, and how it ended.
type Window struct {
	Start, End time.Time
	Requested  time.Duration
	How        pb.WindowEnd
}

// Builder aggregates one window's events into a CaptureReport. It is safe for
// concurrent use.
type Builder struct {
	mu      sync.Mutex
	topN    int
	listCap int

	changes []*pb.ProbeTransition
	context *pb.ProcContext

	host    hostAgg
	cost    costAgg
	cpu     series
	prof    profAgg
	threads threadsAgg
	runq    histAgg
	pauses  histAgg
	mem     memAgg
	heap    heapAgg
	sys     sysAgg
	io      ioAgg
	fs      fsAgg
	net     netAgg
	netErr  counts[*pb.NetErrorCount]
	locks   lockAgg
	signals counts[*pb.SignalCount]
	life    lifeAgg
	sec     counts[*pb.SecurityCount]
	fds     fdAgg
}

// New returns an empty Builder.
func New(cfg Config) *Builder {
	b := &Builder{topN: cfg.TopN, listCap: cfg.ListCap}
	if b.topN <= 0 {
		b.topN = DefaultTopN
	}
	if b.listCap <= 0 {
		b.listCap = collector.DefaultListCap
	}
	return b
}

// Close satisfies serve.Sink. There is nothing to flush.
func (b *Builder) Close() error { return nil }

// Emit folds one stream event into the report.
func (b *Builder) Emit(ev *pb.Event) {
	if ev == nil {
		return
	}
	ts := ev.GetTsUnixNano()
	b.mu.Lock()
	defer b.mu.Unlock()

	switch p := ev.GetPayload().(type) {
	case *pb.Event_ProbeChange:
		b.changes = append(b.changes, &pb.ProbeTransition{TsUnixNano: ts, Probe: p.ProbeChange})
	case *pb.Event_ProcContext:
		b.context = p.ProcContext
	case *pb.Event_Host:
		b.host.add(ts, p.Host)
	case *pb.Event_CaptureCost:
		b.cost.add(p.CaptureCost)
	case *pb.Event_Cpu:
		b.cpu.add(p.Cpu.GetUsagePct())
	case *pb.Event_CpuProfile:
		b.prof.add(ts, p.CpuProfile)
	case *pb.Event_Threads:
		b.threads.add(p.Threads)
	case *pb.Event_RunqLatency:
		b.runq.add(ts, p.RunqLatency.GetCount(), p.RunqLatency.GetSumNs(), p.RunqLatency.GetBuckets())
	case *pb.Event_GoPauses:
		b.pauses.add(ts, p.GoPauses.GetCount(), p.GoPauses.GetSumNs(), p.GoPauses.GetBuckets())
	case *pb.Event_Memory:
		b.mem.add(ts, p.Memory)
	case *pb.Event_Heap:
		b.heap.add(ts, p.Heap)
	case *pb.Event_Syscalls:
		b.sys.add(ts, p.Syscalls)
	case *pb.Event_Io:
		b.io.add(ts, p.Io)
	case *pb.Event_IoThroughput:
		b.io.readBps.add(p.IoThroughput.GetReadBytesPerS())
		b.io.writeBps.add(p.IoThroughput.GetWriteBytesPerS())
	case *pb.Event_IoWait:
		b.io.wait.add(p.IoWait.GetPct())
	case *pb.Event_FsEvent:
		b.fs.add(p.FsEvent)
	case *pb.Event_NetThroughput:
		b.net.addThroughput(ts, p.NetThroughput)
	case *pb.Event_Network:
		b.net.addConns(ts, p.Network)
	case *pb.Event_NetError:
		e := p.NetError
		b.netErr.add(e.GetKind()+"\x00"+e.GetRemote(), func() *pb.NetErrorCount {
			return &pb.NetErrorCount{Kind: e.GetKind(), Remote: e.GetRemote()}
		})
	case *pb.Event_Locks:
		b.locks.add(ts, p.Locks, b.listCap)
	case *pb.Event_Signal:
		s := p.Signal
		b.signals.add(s.GetSignal()+"\x00"+s.GetSenderComm(), func() *pb.SignalCount {
			return &pb.SignalCount{Signal: s.GetSignal(), SenderComm: s.GetSenderComm()}
		})
	case *pb.Event_ProcLifecycle:
		b.life.add(p.ProcLifecycle)
	case *pb.Event_Security:
		b.addSecurity(p.Security)
	case *pb.Event_Fds:
		b.fds.add(p.Fds)
	case *pb.Event_FdEvent:
		b.fds.events++
	}
}

// Report renders what the Builder has seen. target is the handshake of the
// stream the events came from; it says which probes ran, and therefore which
// sections are absent for want of a probe rather than for want of events.
func (b *Builder) Report(target *pb.TargetInfo, w Window) *pb.CaptureReport {
	b.mu.Lock()
	defer b.mu.Unlock()

	n := b.topN
	r := &pb.CaptureReport{
		Target: target,
		Window: &pb.CaptureWindow{
			StartUnixNano: w.Start.UnixNano(),
			EndUnixNano:   w.End.UnixNano(),
			RequestedMs:   uint64(w.Requested.Milliseconds()),
			DurationMs:    uint64(max(w.End.Sub(w.Start), 0).Milliseconds()),
			End:           w.How,
			TopN:          uint32(n),
		},
		ProbeChanges: b.changes,
		Context:      b.context,
		Host:         b.host.report(),
		Cost:         b.cost.report(),
		CpuProfile:   b.prof.report(n),
		Threads:      b.threadsReport(n),
		Memory:       b.mem.report(),
		Heap:         b.heap.report(n),
		Syscalls:     b.sys.report(n),
		Io:           b.ioReport(target, n),
		Network:      b.netReport(target, n),
		Locks:        b.locks.report(n),
		Fds:          b.fds.report(),
	}
	if d := b.cpu.dist(); d != nil {
		r.Cpu = &pb.CpuReport{UsagePct: d}
	}
	if b.signals.seen() || ebpfActive(target, collector.SubsystemSignals) {
		top, omitted := b.signals.top(n)
		r.Signals = &pb.SignalsReport{Total: b.signals.total, Signals: top, Omitted: omitted}
	}
	if b.life.any() || ebpfActive(target, collector.SubsystemLifecycle) {
		r.Lifecycle = b.life.report(n)
	}
	if b.sec.seen() || ebpfActive(target, collector.SubsystemSecurity) {
		r.Security = b.secReport(n)
	}
	return r
}

// ebpfActive reports whether the named probe ran on its eBPF lane, the only
// lane that sees the events its section counts. Its zeros are measurements
// then; otherwise the section is absent and target.probes says why.
func ebpfActive(target *pb.TargetInfo, name string) bool {
	for _, p := range target.GetProbes() {
		if p.GetName() == name {
			return p.GetState() == pb.ProbeState_PROBE_STATE_ACTIVE && p.GetSource() == "eBPF"
		}
	}
	return false
}

// ─── Building blocks ────────────────────────────────────────────────────────

// series is the readings of one value, in arrival order.
type series []float64

func (s *series) add(v float64) { *s = append(*s, v) }

// dist summarizes the readings; nil when there are none.
func (s series) dist() *pb.Distribution {
	if len(s) == 0 {
		return nil
	}
	sorted := append([]float64(nil), s...)
	sort.Float64s(sorted)
	var sum float64
	for _, v := range s {
		sum += v
	}
	return &pb.Distribution{
		N:     uint32(len(s)),
		Min:   sorted[0],
		Mean:  sum / float64(len(s)),
		P50:   nearestRank(sorted, 50),
		P95:   nearestRank(sorted, 95),
		Max:   sorted[len(sorted)-1],
		First: s[0],
		Last:  s[len(s)-1],
	}
}

// nearestRank is the p-th percentile of sorted values: the smallest value at
// or above which p percent of the readings lie. It is always a reading, never
// an interpolation between two.
func nearestRank(sorted []float64, p float64) float64 {
	r := int(math.Ceil(p / 100 * float64(len(sorted))))
	r = max(r, 1)
	return sorted[r-1]
}

// span is when an axis's readings arrived. The first is the baseline of the
// axis's totals.
type span struct {
	n           uint32
	first, last int64
}

// add records a reading and reports whether it is the baseline.
func (s *span) add(ts int64) (baseline bool) {
	s.n++
	if s.n == 1 {
		s.first = ts
	}
	s.last = ts
	return s.n == 1
}

// ms is the time from the baseline to the last reading.
func (s span) ms() uint64 {
	if s.n < 2 || s.last <= s.first {
		return 0
	}
	return uint64((s.last - s.first) / int64(time.Millisecond))
}

// mono is one cumulative counter over a span: its value at the baseline
// reading and the highest value since. A counter first seen after the baseline
// started at zero. One that went backwards (a kernel entry evicted and
// recreated) keeps its high-water mark, so the difference never goes negative
// and no stretch is counted twice.
type mono struct{ base, top uint64 }

func (m *mono) see(v uint64, baseline bool) {
	if baseline {
		m.base, m.top = v, v
		return
	}
	m.top = max(m.top, v)
}

func (m mono) delta() uint64 { return m.top - m.base }

// nanos converts a mean in milliseconds over n calls back to the sum it was
// taken from, which is what a difference between two readings needs.
func nanos(meanMs float64, n uint64) uint64 {
	return uint64(math.Round(meanMs * 1e6 * float64(n)))
}

// ranked sorts rows by key, descending, ties broken by name so a report is
// the same however a map was iterated, and splits them at n.
func ranked[T any](rows []T, n int, key func(T) float64, name func(T) string) (top, rest []T) {
	sort.SliceStable(rows, func(i, j int) bool {
		ki, kj := key(rows[i]), key(rows[j])
		if ki != kj {
			return ki > kj
		}
		return name(rows[i]) < name(rows[j])
	})
	if len(rows) <= n {
		return rows, nil
	}
	return rows[:n], rows[n:]
}

// counts tallies events by a key, keeping one message per key to report.
type counts[T proto.Message] struct {
	total uint64
	rows  map[string]T
	n     map[string]uint64
}

func (c *counts[T]) add(key string, mk func() T) {
	if c.rows == nil {
		c.rows, c.n = make(map[string]T), make(map[string]uint64)
	}
	c.total++
	if _, ok := c.rows[key]; !ok {
		c.rows[key] = mk()
	}
	c.n[key]++
}

func (c *counts[T]) seen() bool { return c.total > 0 }

// top returns the n most frequent, with their counts set, and the count of the
// rest.
func (c *counts[T]) top(n int) ([]T, uint64) {
	keys := make([]string, 0, len(c.rows))
	for k := range c.rows {
		keys = append(keys, k)
	}
	top, rest := ranked(keys, n, func(k string) float64 { return float64(c.n[k]) }, func(k string) string { return k })
	out := make([]T, 0, len(top))
	for _, k := range top {
		m := proto.Clone(c.rows[k]).(T)
		setCount(m, c.n[k])
		out = append(out, m)
	}
	var omitted uint64
	for _, k := range rest {
		omitted += c.n[k]
	}
	return out, omitted
}

// setCount writes a tally into whichever count message it is.
func setCount(m proto.Message, n uint64) {
	switch x := m.(type) {
	case *pb.SignalCount:
		x.Count = n
	case *pb.NetErrorCount:
		x.Count = n
	case *pb.SecurityCount:
		x.Count = n
	case *pb.ExecCount:
		x.Count = n
	case *pb.FsEventCount:
		x.Count = n
	}
}

// ─── Context ────────────────────────────────────────────────────────────────

type hostAgg struct {
	span  span
	steal series
	thr   struct {
		n                        uint32
		periods, throttled, usec mono
	}
	press  [3]stallAgg // cpu, memory, io
	limits *pb.CgroupLimits
}

type stallAgg struct {
	n, fullN   uint32
	some, full mono
}

func (s *stallAgg) add(p *pb.Pressure) {
	if p == nil {
		return
	}
	s.n++
	s.some.see(p.GetSome().GetTotalUsec(), s.n == 1)
	if p.GetFull() != nil {
		s.fullN++
		s.full.see(p.GetFull().GetTotalUsec(), s.fullN == 1)
	}
}

func (s stallAgg) report() *pb.StallTime {
	if s.n < 2 {
		return nil
	}
	st := &pb.StallTime{SomeUsec: s.some.delta()}
	if s.fullN >= 2 {
		st.FullUsec = proto.Uint64(s.full.delta())
	}
	return st
}

func (h *hostAgg) add(ts int64, s *pb.HostSample) {
	h.span.add(ts)
	if s.StealPct != nil {
		h.steal.add(s.GetStealPct())
	}
	if t := s.GetThrottling(); t != nil {
		h.thr.n++
		first := h.thr.n == 1
		h.thr.periods.see(t.GetNrPeriods(), first)
		h.thr.throttled.see(t.GetNrThrottled(), first)
		h.thr.usec.see(t.GetThrottledUsec(), first)
	}
	if p := s.GetPressure(); p != nil {
		h.press[0].add(p.GetCpu())
		h.press[1].add(p.GetMemory())
		h.press[2].add(p.GetIo())
	}
	if s.GetLimits() != nil {
		h.limits = s.GetLimits()
	}
}

func (h *hostAgg) report() *pb.HostReport {
	if h.span.n == 0 {
		return nil
	}
	r := &pb.HostReport{Readings: h.span.n, SpanMs: h.span.ms(), StealPct: h.steal.dist(), Limits: h.limits}
	if h.thr.n >= 2 {
		r.Throttling = &pb.CpuThrottling{
			NrPeriods:     h.thr.periods.delta(),
			NrThrottled:   h.thr.throttled.delta(),
			ThrottledUsec: h.thr.usec.delta(),
		}
	}
	cpu, mem, io := h.press[0].report(), h.press[1].report(), h.press[2].report()
	if cpu != nil || mem != nil || io != nil {
		r.Pressure = &pb.PressureReport{Cpu: cpu, Memory: mem, Io: io}
	}
	return r
}

type costAgg struct {
	n      uint32
	ptop   series
	probes map[string]*probeCostAgg
	order  []string
}

type probeCostAgg struct {
	est, share       series
	entries, returns uint64
	calibration      string
}

func (c *costAgg) add(cc *pb.CaptureCost) {
	c.n++
	if cc.PtopCpuPct != nil {
		c.ptop.add(cc.GetPtopCpuPct())
	}
	for _, p := range cc.GetProbes() {
		if c.probes == nil {
			c.probes = make(map[string]*probeCostAgg)
		}
		a := c.probes[p.GetProbe()]
		if a == nil {
			a = &probeCostAgg{}
			c.probes[p.GetProbe()] = a
			c.order = append(c.order, p.GetProbe())
		}
		a.est.add(p.GetEstimatePct())
		if p.TargetSharePct != nil {
			a.share.add(p.GetTargetSharePct())
		}
		// Hits are per window; the first reading's window began before the
		// report did.
		if c.n > 1 {
			a.entries += p.GetEntries()
			a.returns += p.GetReturns()
		}
		a.calibration = p.GetCalibration()
	}
}

func (c *costAgg) report() *pb.CostReport {
	if c.n == 0 {
		return nil
	}
	r := &pb.CostReport{PtopCpuPct: c.ptop.dist()}
	for _, name := range c.order {
		a := c.probes[name]
		r.Probes = append(r.Probes, &pb.ProbeCostReport{
			Probe: name, EstimatePct: a.est.dist(), TargetSharePct: a.share.dist(),
			Entries: a.entries, Returns: a.returns, Calibration: a.calibration,
		})
	}
	return r
}

// ─── CPU ────────────────────────────────────────────────────────────────────

type profSite struct {
	site            *pb.CpuSite // from the window where it took the most samples
	best            uint64
	samples, kernel uint64
}

type profAgg struct {
	span                      span
	sites                     map[string]*profSite
	total, unresolved, kernel uint64
	windowMs                  uint64
	rateMs                    float64 // Σ sample_rate_hz × window_ms
	requested                 float64
	scope                     pb.StackScope
	truncated                 uint32
}

func (a *profAgg) add(ts int64, p *pb.CpuProfile) {
	a.requested, a.scope = p.GetRequestedRateHz(), p.GetStackScope()
	if a.span.add(ts) {
		return // the baseline's window began before the report did
	}
	if a.sites == nil {
		a.sites = make(map[string]*profSite)
	}
	a.total += p.GetTotalSamples()
	a.unresolved += p.GetUnresolvedSamples()
	a.kernel += p.GetKernelModeSamples()
	a.windowMs += p.GetWindowMs()
	a.rateMs += p.GetSampleRateHz() * float64(p.GetWindowMs())
	if p.GetTotalSites() > uint32(len(p.GetSites())) {
		a.truncated++
	}
	for _, s := range p.GetSites() {
		// The collector's own fold rule, so a function merges across windows
		// exactly as it merged within one.
		k := collector.CPUSite{Func: s.GetFunc(), Module: s.GetModule(), Addr: s.GetAddr()}.Key()
		r := a.sites[k]
		if r == nil {
			r = &profSite{}
			a.sites[k] = r
		}
		r.samples += s.GetSamples()
		r.kernel += s.GetKernelModeSamples()
		if r.site == nil || s.GetSamples() > r.best {
			r.site, r.best = s, s.GetSamples()
		}
	}
}

func (a *profAgg) report(n int) *pb.CpuProfileReport {
	if a.span.n == 0 {
		return nil
	}
	r := &pb.CpuProfileReport{
		Readings:          a.span.n,
		SpanMs:            a.windowMs,
		TotalSamples:      a.total,
		UnresolvedSamples: a.unresolved,
		KernelModeSamples: a.kernel,
		TotalSites:        uint32(len(a.sites)),
		TruncatedReadings: a.truncated,
		RequestedRateHz:   a.requested,
		StackScope:        a.scope,
	}
	if a.windowMs > 0 {
		r.SampleRateHz = a.rateMs / float64(a.windowMs)
	}
	rows := make([]*profSite, 0, len(a.sites))
	for _, s := range a.sites {
		rows = append(rows, s)
	}
	top, _ := ranked(rows, n,
		func(s *profSite) float64 { return float64(s.samples) },
		func(s *profSite) string {
			return collector.CPUSite{Func: s.site.GetFunc(), Module: s.site.GetModule(), Addr: s.site.GetAddr()}.Key()
		})
	listed := uint64(0)
	for _, s := range top {
		site := proto.Clone(s.site).(*pb.CpuSite)
		site.Samples, site.KernelModeSamples = s.samples, s.kernel
		site.SharePct = share(s.samples, a.total)
		r.Sites = append(r.Sites, site)
		listed += s.samples
	}
	// Everything not in a listed site's count: the functions cut here and the
	// ones each window's own list had already cut.
	if seen := a.unresolved + listed; a.total > seen {
		r.OmittedSamples = a.total - seen
	}
	return r
}

func share(part, whole uint64) float64 {
	if whole == 0 {
		return 0
	}
	return float64(part) / float64(whole) * 100
}

// ─── Threads ────────────────────────────────────────────────────────────────

type threadRow struct {
	tid                  int32
	name, state, waiting string
	n                    uint32
	cpu, off, runq       float64 // summed over its readings
	ctx                  uint64
}

type threadsAgg struct {
	readings uint32
	count    series
	rows     map[int32]*threadRow
}

func (a *threadsAgg) add(s *pb.ThreadSnapshot) {
	a.readings++
	a.count.add(float64(len(s.GetThreads())))
	if a.rows == nil {
		a.rows = make(map[int32]*threadRow)
	}
	for _, t := range s.GetThreads() {
		r := a.rows[t.GetTid()]
		if r == nil {
			r = &threadRow{tid: t.GetTid()}
			a.rows[t.GetTid()] = r
		}
		r.name, r.state, r.waiting = t.GetName(), t.GetState(), t.GetWaiting()
		r.n++
		r.cpu += t.GetCpuPct()
		r.off += t.GetOffCpuPct()
		r.runq += t.GetRunqWaitPct()
		r.ctx += t.GetCtxSwitches()
	}
}

func (b *Builder) threadsReport(n int) *pb.ThreadsReport {
	a := &b.threads
	runq, pauses := b.runq.report(), b.pauses.report()
	if a.readings == 0 && runq == nil && pauses == nil {
		return nil
	}
	r := &pb.ThreadsReport{
		Readings:     a.readings,
		Count:        a.count.dist(),
		TotalThreads: uint32(len(a.rows)),
		RunqLatency:  runq,
		GoPauses:     pauses,
	}
	rows := make([]*threadRow, 0, len(a.rows))
	for _, t := range a.rows {
		rows = append(rows, t)
	}
	// On-CPU time over the window is the sum of a thread's per-reading shares.
	top, rest := ranked(rows, n,
		func(t *threadRow) float64 { return t.cpu },
		func(t *threadRow) string { return fmt.Sprintf("%010d", t.tid) })
	for _, t := range top {
		k := float64(t.n)
		r.Threads = append(r.Threads, &pb.ThreadSummary{
			Tid: t.tid, Name: t.name, Readings: t.n,
			CpuPct: t.cpu / k, OffCpuPct: t.off / k, RunqWaitPct: t.runq / k,
			CtxSwitches: t.ctx, State: t.state, Waiting: t.waiting,
		})
	}
	for _, t := range rest {
		r.OmittedCpuPct += t.cpu
	}
	if a.readings > 0 {
		r.OmittedCpuPct /= float64(a.readings)
	}
	return r
}

type histAgg struct {
	span       span
	count, sum mono
	buckets    []mono
}

func (h *histAgg) add(ts int64, count, sum uint64, buckets []uint64) {
	base := h.span.add(ts)
	h.count.see(count, base)
	h.sum.see(sum, base)
	for len(h.buckets) < len(buckets) {
		h.buckets = append(h.buckets, mono{})
	}
	for i, v := range buckets {
		h.buckets[i].see(v, base)
	}
}

func (h *histAgg) report() *pb.LatencyHistogram {
	if h.span.n == 0 {
		return nil
	}
	r := &pb.LatencyHistogram{Readings: h.span.n, SpanMs: h.span.ms(), Count: h.count.delta(), SumNs: h.sum.delta()}
	for _, b := range h.buckets {
		r.Buckets = append(r.Buckets, b.delta())
	}
	return r
}

// ─── Memory ─────────────────────────────────────────────────────────────────

type memAgg struct {
	span      span
	rss, heap series
	faults    mono
}

func (m *memAgg) add(ts int64, s *pb.MemStats) {
	base := m.span.add(ts)
	m.rss.add(float64(s.GetRssBytes()))
	m.heap.add(float64(s.GetHeapBytes()))
	m.faults.see(s.GetPageFaults(), base)
}

func (m *memAgg) report() *pb.MemoryReport {
	if m.span.n == 0 {
		return nil
	}
	return &pb.MemoryReport{
		Readings: m.span.n, SpanMs: m.span.ms(),
		RssBytes: m.rss.dist(), HeapBytes: m.heap.dist(),
		PageFaults: m.faults.delta(),
	}
}

type heapRow struct {
	site         *pb.HeapCallSite // its last reading
	count, bytes mono
}

type heapAgg struct {
	span          span
	lane          string
	liveMeasured  bool
	sampleBytes   uint64
	allocs, bytes float64 // each reading's rate × its interval, summed
	prevTs        int64
	live          series
	rows          map[uint64]*heapRow // Go lane, by call site
	all           struct{ count, bytes mono }
	last          *pb.HeapSnapshot // libc lane: the list is the last reading's
	truncated     uint32
}

func (a *heapAgg) add(ts int64, h *pb.HeapSnapshot) {
	base := a.span.add(ts)
	a.lane, a.liveMeasured, a.sampleBytes = h.GetLane(), h.GetLiveMeasured(), h.GetSampleBytes()
	if h.GetLiveMeasured() {
		a.live.add(float64(h.GetLiveHeapBytes()))
	}
	// A reading's rate is over the interval since the previous one, measured
	// on the clock that stamped both.
	if !base && ts > a.prevTs {
		dt := float64(ts-a.prevTs) / 1e9
		a.allocs += h.GetAllocRate() * dt
		a.bytes += h.GetAllocBytesRate() * dt
	}
	a.prevTs = ts
	a.last = h
	if h.GetLane() != collector.HeapLaneGo {
		return
	}
	if h.GetTotalCallSites() > uint32(len(h.GetTopCallSites())) {
		a.truncated++
	}
	if a.rows == nil {
		a.rows = make(map[uint64]*heapRow)
	}
	count, bytes := h.GetOmittedAllocCount(), h.GetOmittedAllocBytes()
	for _, s := range h.GetTopCallSites() {
		r := a.rows[s.GetCallSite()]
		if r == nil {
			r = &heapRow{}
			a.rows[s.GetCallSite()] = r
		}
		r.site = s
		r.count.see(s.GetAllocCount(), base)
		r.bytes.see(s.GetAllocBytes(), base)
		count += s.GetAllocCount()
		bytes += s.GetAllocBytes()
	}
	// Every site's allocations, listed or cut, as one cumulative counter: what
	// the report's own cut leaves out is this less what it lists.
	a.all.count.see(count, base)
	a.all.bytes.see(bytes, base)
}

func (a *heapAgg) report(n int) *pb.HeapReport {
	if a.span.n == 0 {
		return nil
	}
	r := &pb.HeapReport{
		Lane: a.lane, LiveMeasured: a.liveMeasured, SampleBytes: a.sampleBytes,
		Readings: a.span.n, SpanMs: a.span.ms(),
		AllocCount: uint64(math.Round(a.allocs)), AllocBytes: uint64(math.Round(a.bytes)),
		LiveHeapBytes: a.live.dist(),
	}
	if a.lane != collector.HeapLaneGo {
		a.libcSites(r, n)
		return r
	}
	r.TruncatedReadings = a.truncated
	rows := make([]*heapRow, 0, len(a.rows))
	for _, s := range a.rows {
		if s.count.delta() > 0 || s.bytes.delta() > 0 {
			rows = append(rows, s)
		}
	}
	r.TotalCallSites = uint32(len(rows))
	top, _ := ranked(rows, n,
		func(s *heapRow) float64 { return float64(s.bytes.delta()) },
		func(s *heapRow) string { return s.site.GetAddrHex() })
	var count, bytes uint64
	for _, s := range top {
		site := proto.Clone(s.site).(*pb.HeapCallSite)
		site.AllocCount, site.AllocBytes = s.count.delta(), s.bytes.delta()
		r.Sites = append(r.Sites, site)
		count += site.AllocCount
		bytes += site.AllocBytes
	}
	r.OmittedAllocCount = sub(a.all.count.delta(), count)
	r.OmittedAllocBytes = sub(a.all.bytes.delta(), bytes)
	return r
}

// libcSites lists the live set at the last reading: the libc lane keeps live
// allocations per site, not what each site allocated over time.
func (a *heapAgg) libcSites(r *pb.HeapReport, n int) {
	h := a.last
	sites := append([]*pb.HeapCallSite(nil), h.GetTopCallSites()...)
	top, rest := ranked(sites, n,
		func(s *pb.HeapCallSite) float64 { return float64(s.GetLiveBytes()) },
		func(s *pb.HeapCallSite) string { return s.GetAddrHex() })
	r.Sites = top
	r.TotalCallSites = h.GetTotalCallSites()
	r.OmittedAllocCount = h.GetOmittedAllocCount()
	r.OmittedAllocBytes = h.GetOmittedAllocBytes()
	r.OmittedLiveBytes = h.GetOmittedLiveBytes()
	for _, s := range rest {
		r.OmittedAllocCount += s.GetAllocCount()
		r.OmittedAllocBytes += s.GetAllocBytes()
		r.OmittedLiveBytes += s.GetLiveBytes()
	}
}

func sub(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

// ─── Syscalls ───────────────────────────────────────────────────────────────

type sysRow struct {
	name       string
	count, lat mono
	timed      bool
	classes    map[string]*sysClass
}

type sysClass struct{ count, lat mono }

type sysAgg struct {
	span span
	rows map[string]*sysRow
}

func (a *sysAgg) add(ts int64, s *pb.SyscallSnapshot) {
	base := a.span.add(ts)
	if a.rows == nil {
		a.rows = make(map[string]*sysRow)
	}
	for _, st := range s.GetStats() {
		r := a.rows[st.GetName()]
		if r == nil {
			r = &sysRow{name: st.GetName(), classes: make(map[string]*sysClass)}
			a.rows[st.GetName()] = r
		}
		r.count.see(st.GetCount(), base)
		if st.LatencyNs != nil {
			r.timed = true
			r.lat.see(st.GetLatencyNs(), base)
		}
		for _, fc := range st.GetFdClasses() {
			c := r.classes[fc.GetFdClass()]
			if c == nil {
				c = &sysClass{}
				r.classes[fc.GetFdClass()] = c
			}
			c.count.see(fc.GetCount(), base)
			c.lat.see(fc.GetLatencyNs(), base)
		}
	}
}

func (a *sysAgg) report(n int) *pb.SyscallsReport {
	if a.span.n == 0 {
		return nil
	}
	r := &pb.SyscallsReport{Readings: a.span.n, SpanMs: a.span.ms()}
	timed := false
	rows := make([]*sysRow, 0, len(a.rows))
	for _, s := range a.rows {
		if s.count.delta() == 0 {
			continue
		}
		rows = append(rows, s)
		timed = timed || s.timed
		r.Count += s.count.delta()
	}
	r.TotalSyscalls = uint32(len(rows))
	key := func(s *sysRow) float64 { return float64(s.count.delta()) }
	if timed {
		key = func(s *sysRow) float64 { return float64(s.lat.delta()) }
	}
	top, rest := ranked(rows, n, key, func(s *sysRow) string { return s.name })
	var lat, omittedLat uint64
	for _, s := range top {
		st := &pb.SyscallStat{Name: s.name, Count: s.count.delta()}
		if s.timed {
			st.LatencyNs = proto.Uint64(s.lat.delta())
		}
		names := make([]string, 0, len(s.classes))
		for c := range s.classes {
			names = append(names, c)
		}
		sort.Strings(names)
		for _, c := range names {
			fc := s.classes[c]
			if fc.count.delta() > 0 {
				st.FdClasses = append(st.FdClasses, &pb.FdClassStat{FdClass: c, Count: fc.count.delta(), LatencyNs: fc.lat.delta()})
			}
		}
		r.Syscalls = append(r.Syscalls, st)
		lat += s.lat.delta()
	}
	for _, s := range rest {
		r.OmittedCount += s.count.delta()
		omittedLat += s.lat.delta()
	}
	if timed {
		r.LatencyNs = proto.Uint64(lat + omittedLat)
		r.OmittedLatencyNs = proto.Uint64(omittedLat)
	}
	return r
}

// ─── I/O ────────────────────────────────────────────────────────────────────

type ioRow struct {
	path, typ                 string
	reads, writes, bytes, lat mono
}

type ioAgg struct {
	span     span
	rows     map[string]*ioRow
	labels   []string
	buckets  map[string]*[2]float64 // label → read, write
	readBps  series
	writeBps series
	wait     series
}

func (a *ioAgg) add(ts int64, s *pb.IoSnapshot) {
	base := a.span.add(ts)
	if a.rows == nil {
		a.rows = make(map[string]*ioRow)
		a.buckets = make(map[string]*[2]float64)
	}
	for _, f := range s.GetTopFiles() {
		r := a.rows[f.GetPath()]
		if r == nil {
			r = &ioRow{path: f.GetPath()}
			a.rows[f.GetPath()] = r
		}
		r.typ = f.GetType()
		r.reads.see(f.GetReads(), base)
		r.writes.see(f.GetWrites(), base)
		r.bytes.see(f.GetBytes(), base)
		r.lat.see(nanos(f.GetLatencyMs(), f.GetReads()+f.GetWrites()), base)
	}
	for _, b := range s.GetLatencyBuckets() {
		c := a.buckets[b.GetLabel()]
		if c == nil {
			c = &[2]float64{}
			a.buckets[b.GetLabel()] = c
			a.labels = append(a.labels, b.GetLabel())
		}
		if !base { // the baseline's window began before the report did
			c[0] += b.GetRead()
			c[1] += b.GetWrite()
		}
	}
}

func (b *Builder) ioReport(target *pb.TargetInfo, n int) *pb.IoReport {
	a := &b.io
	fs := b.fsReport(target, n)
	if a.span.n == 0 && len(a.readBps) == 0 && len(a.wait) == 0 && fs == nil {
		return nil
	}
	r := &pb.IoReport{
		Readings: a.span.n, SpanMs: a.span.ms(),
		ReadBytesPerS: a.readBps.dist(), WriteBytesPerS: a.writeBps.dist(), IoWaitPct: a.wait.dist(),
		Fs: fs,
	}
	rows := make([]*ioRow, 0, len(a.rows))
	for _, f := range a.rows {
		if f.reads.delta()+f.writes.delta() > 0 {
			rows = append(rows, f)
		}
	}
	r.TotalFiles = uint32(len(rows))
	top, rest := ranked(rows, n,
		func(f *ioRow) float64 { return float64(f.lat.delta()) },
		func(f *ioRow) string { return f.path })
	for _, f := range top {
		r.Files = append(r.Files, &pb.IoFile{
			Path: f.path, Type: f.typ,
			Reads: f.reads.delta(), Writes: f.writes.delta(), Bytes: f.bytes.delta(), LatencyNs: f.lat.delta(),
		})
	}
	for _, f := range rest {
		r.OmittedReads += f.reads.delta()
		r.OmittedWrites += f.writes.delta()
		r.OmittedBytes += f.bytes.delta()
		r.OmittedLatencyNs += f.lat.delta()
	}
	if a.span.n > 0 {
		for _, l := range a.labels {
			c := a.buckets[l]
			r.LatencyBuckets = append(r.LatencyBuckets, &pb.LatencyBucket{Label: l, Read: c[0], Write: c[1]})
		}
	}
	return r
}

type fsAgg struct {
	counts                   counts[*pb.FsEventCount]
	denied, deleted, renamed uint64
}

func (a *fsAgg) add(e *pb.FSEvent) {
	switch e.GetOp() {
	case "denied":
		a.denied++
	case "deleted":
		a.deleted++
	case "renamed":
		a.renamed++
	}
	key := e.GetOp() + "\x00" + e.GetPath() + "\x00" + e.GetNewPath() + "\x00" + e.GetErr()
	a.counts.add(key, func() *pb.FsEventCount {
		return &pb.FsEventCount{Op: e.GetOp(), Path: e.GetPath(), NewPath: e.GetNewPath(), Err: e.GetErr()}
	})
}

func (b *Builder) fsReport(target *pb.TargetInfo, n int) *pb.FsEventsReport {
	a := &b.fs
	if !a.counts.seen() && !ebpfActive(target, collector.SubsystemIO) {
		return nil
	}
	top, omitted := a.counts.top(n)
	return &pb.FsEventsReport{
		Total: a.counts.total, Denied: a.denied, Deleted: a.deleted, Renamed: a.renamed,
		Events: top, Omitted: omitted,
	}
}

// ─── Network ────────────────────────────────────────────────────────────────

type connRow struct {
	key    string
	conn   *pb.NetConn // its last reading
	tx, rx mono
}

type netAgg struct {
	tp              span
	tx, rx, dropped mono
	conns           span
	rows            map[string]*connRow
}

func (a *netAgg) addThroughput(ts int64, s *pb.NetThroughputSample) {
	base := a.tp.add(ts)
	a.tx.see(s.GetTxBytes(), base)
	a.rx.see(s.GetRxBytes(), base)
	a.dropped.see(s.GetDroppedConnections(), base)
}

func (a *netAgg) addConns(ts int64, s *pb.NetworkSnapshot) {
	base := a.conns.add(ts)
	if a.rows == nil {
		a.rows = make(map[string]*connRow)
	}
	for _, c := range s.GetConns() {
		k := c.GetType() + "\x00" + c.GetRemote() + "\x00" + strconv.Itoa(int(c.GetFd()))
		r := a.rows[k]
		if r == nil {
			r = &connRow{key: k}
			a.rows[k] = r
		}
		r.conn = c
		r.tx.see(c.GetTxBytes(), base)
		r.rx.see(c.GetRxBytes(), base)
	}
}

func (b *Builder) netReport(target *pb.TargetInfo, n int) *pb.NetworkReport {
	a := &b.net
	measured := ebpfActive(target, collector.SubsystemNetwork)
	if a.tp.n == 0 && a.conns.n == 0 && !b.netErr.seen() && !measured {
		return nil
	}
	r := &pb.NetworkReport{
		Readings: a.tp.n, SpanMs: a.tp.ms(),
		TxBytes: a.tx.delta(), RxBytes: a.rx.delta(), DroppedConnections: a.dropped.delta(),
		TotalConns: uint32(len(a.rows)),
	}
	rows := make([]*connRow, 0, len(a.rows))
	for _, c := range a.rows {
		rows = append(rows, c)
	}
	top, rest := ranked(rows, n,
		func(c *connRow) float64 { return float64(c.tx.delta() + c.rx.delta()) },
		func(c *connRow) string { return c.key })
	for _, c := range top {
		conn := proto.Clone(c.conn).(*pb.NetConn)
		conn.TxBytes, conn.RxBytes = c.tx.delta(), c.rx.delta()
		r.Conns = append(r.Conns, conn)
	}
	for _, c := range rest {
		r.OmittedTxBytes += c.tx.delta()
		r.OmittedRxBytes += c.rx.delta()
	}
	if b.netErr.seen() || measured {
		r.Errors = proto.Uint64(b.netErr.total)
		r.ErrorCounts, r.OmittedErrors = b.netErr.top(n)
	}
	return r
}

// ─── Locks ──────────────────────────────────────────────────────────────────

type lockRow struct {
	entry                *pb.LockEntry // its last reading
	waits, wakes, waitNs mono
}

type lockAgg struct {
	span      span
	rows      map[uint64]*lockRow
	truncated uint32
}

func (a *lockAgg) add(ts int64, s *pb.LockSnapshot, listCap int) {
	base := a.span.add(ts)
	if len(s.GetLocks()) >= listCap {
		a.truncated++ // the list does not say what it cut, so assume it did
	}
	if a.rows == nil {
		a.rows = make(map[uint64]*lockRow)
	}
	for _, l := range s.GetLocks() {
		r := a.rows[l.GetUaddr()]
		if r == nil {
			r = &lockRow{}
			a.rows[l.GetUaddr()] = r
		}
		r.entry = l
		r.waits.see(l.GetWaiters(), base)
		r.wakes.see(l.GetWakers(), base)
		r.waitNs.see(nanos(l.GetLatencyMs(), l.GetWaiters()), base)
	}
}

func (a *lockAgg) report(n int) *pb.LocksReport {
	if a.span.n == 0 {
		return nil
	}
	r := &pb.LocksReport{Readings: a.span.n, SpanMs: a.span.ms(), TruncatedReadings: a.truncated}
	rows := make([]*lockRow, 0, len(a.rows))
	for _, l := range a.rows {
		if l.waits.delta() > 0 {
			rows = append(rows, l)
			r.Waits += l.waits.delta()
			r.WaitNs += l.waitNs.delta()
		}
	}
	r.TotalLocks = uint32(len(rows))
	top, rest := ranked(rows, n,
		func(l *lockRow) float64 { return float64(l.waitNs.delta()) },
		func(l *lockRow) string { return fmt.Sprintf("%016x", l.entry.GetUaddr()) })
	for _, l := range top {
		r.Locks = append(r.Locks, &pb.LockSummary{
			Uaddr: l.entry.GetUaddr(), Waits: l.waits.delta(), Wakes: l.wakes.delta(), WaitNs: l.waitNs.delta(),
			CallSite: l.entry.GetCallSite(), StackId: l.entry.GetStackId(),
		})
	}
	for _, l := range rest {
		r.OmittedWaits += l.waits.delta()
		r.OmittedWaitNs += l.waitNs.delta()
	}
	return r
}

// ─── Events ─────────────────────────────────────────────────────────────────

type lifeAgg struct {
	forks, exits uint64
	execs        counts[*pb.ExecCount]
}

func (a *lifeAgg) add(e *pb.ProcLifecycleEvent) {
	switch e.GetKind() {
	case "fork":
		a.forks++
	case "exit":
		a.exits++
	case "exec":
		a.execs.add(e.GetFilename(), func() *pb.ExecCount { return &pb.ExecCount{Filename: e.GetFilename()} })
	}
}

func (a *lifeAgg) any() bool { return a.forks+a.exits > 0 || a.execs.seen() }

func (a *lifeAgg) report(n int) *pb.LifecycleReport {
	top, omitted := a.execs.top(n)
	return &pb.LifecycleReport{Forks: a.forks, Execs: a.execs.total, Exits: a.exits, ExecFiles: top, OmittedExecs: omitted}
}

func (b *Builder) addSecurity(e *pb.SecurityEvent) {
	cs := e.GetCallSite()
	key := e.GetKind() + "\x00" + e.GetOp() + "\x00" + cs.GetModule() + "\x00" + cs.GetFunc() + "\x00" +
		strconv.FormatUint(cs.GetOffset(), 16) + "\x00" + e.GetDetail() + "\x00" + boolKey(e.GetWriteExec()) + boolKey(e.GetAnon())
	b.sec.add(key, func() *pb.SecurityCount {
		return &pb.SecurityCount{
			Kind: e.GetKind(), Op: e.GetOp(), CallSite: cs, Detail: e.GetDetail(),
			WriteExec: e.GetWriteExec(), Anon: e.GetAnon(),
		}
	})
}

func boolKey(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func (b *Builder) secReport(n int) *pb.SecurityReport {
	r := &pb.SecurityReport{}
	for k, m := range b.sec.rows {
		c := b.sec.n[k]
		switch m.GetKind() {
		case "exec-map":
			r.ExecMaps += c
		case "lsm-decision":
			r.LsmDecisions += c
		}
		if m.GetWriteExec() {
			r.WriteExec += c
		}
		if m.GetAnon() {
			r.Anon += c
		}
	}
	r.Events, r.Omitted = b.sec.top(n)
	return r
}

type fdAgg struct {
	readings uint32
	open     series
	types    map[string]uint32 // at the last reading
	events   uint64
}

func (a *fdAgg) add(s *pb.FdSnapshot) {
	a.readings++
	a.open.add(float64(len(s.GetFds())))
	a.types = make(map[string]uint32)
	for _, f := range s.GetFds() {
		a.types[f.GetType()]++
	}
}

func (a *fdAgg) report() *pb.FdReport {
	if a.readings == 0 {
		return nil
	}
	r := &pb.FdReport{Readings: a.readings, Open: a.open.dist(), Events: a.events}
	names := make([]string, 0, len(a.types))
	for t := range a.types {
		names = append(names, t)
	}
	top, _ := ranked(names, len(names),
		func(t string) float64 { return float64(a.types[t]) },
		func(t string) string { return t })
	for _, t := range top {
		r.Types = append(r.Types, &pb.FdTypeCount{Type: t, Count: a.types[t]})
	}
	return r
}
