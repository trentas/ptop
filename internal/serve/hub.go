package serve

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/trentas/ptop/pkg/collector"
	pb "github.com/trentas/ptop/pkg/streampb"
)

// Hub fans collector events in from many channels and out to many Sinks. One
// Hub per server instance (one target). Sinks are interchangeable consumers of
// the unified event stream: a gRPC subscriber and a JSONL writer are both just
// Sinks (see sink.go).
type Hub struct {
	target  Target
	buildID string          // target exec build-id, stamped onto every StackRef (#54)
	probes  []*pb.ProbeInfo // what became of each collector, for the handshake (#112)
	mu      sync.Mutex
	sinks   map[Sink]struct{}

	// Execution-context identity (#60) stamped onto every outgoing envelope.
	// Updated whenever a ProcContext snapshot flows through; zero until the
	// first one is observed (and on platforms without /proc).
	identMu  sync.Mutex
	uid, gid uint32
	cgroupID uint64
}

// NewHub builds the hub for one target. set is the running collectors behind it,
// whose per-probe outcome goes into the handshake (#112); nil is accepted and
// yields an empty probe set, which a consumer reads as "unknown", not as "none".
func NewHub(target Target, buildID string, set *collector.Set) *Hub {
	return &Hub{
		target:  target,
		buildID: buildID,
		probes:  probeInfos(set),
		sinks:   make(map[Sink]struct{}),
	}
}

// targetInfo renders the handshake every subscriber receives before its first
// event, so a consumer knows the scope of what follows (#94) and which probes
// produced it (#112).
func (h *Hub) targetInfo() *pb.TargetInfo {
	if h.target.IsCgroup() {
		return &pb.TargetInfo{
			Mode:       pb.TargetMode_TARGET_MODE_CGROUP,
			CgroupPath: h.target.CgroupPath,
			CgroupId:   h.target.CgroupID,
			Probes:     h.probes,
		}
	}
	return &pb.TargetInfo{
		Mode:   pb.TargetMode_TARGET_MODE_PID,
		Pid:    int32(h.target.PID),
		Probes: h.probes,
	}
}

// probeStates maps the collector package's outcome onto the wire enum. An
// unknown state becomes UNSPECIFIED rather than a guess: a consumer that treats
// "I don't know" as "active" is the failure this whole field exists to prevent.
var probeStates = map[collector.ProbeState]pb.ProbeState{
	collector.ProbeActive:      pb.ProbeState_PROBE_STATE_ACTIVE,
	collector.ProbeDisabled:    pb.ProbeState_PROBE_STATE_DISABLED,
	collector.ProbeFailed:      pb.ProbeState_PROBE_STATE_FAILED,
	collector.ProbeUnsupported: pb.ProbeState_PROBE_STATE_UNSUPPORTED,
}

// probeInfos renders a Set's probe outcomes for the handshake, in the sorted
// order Set.Probes guarantees.
func probeInfos(set *collector.Set) []*pb.ProbeInfo {
	sts := set.Probes()
	if len(sts) == 0 {
		return nil
	}
	out := make([]*pb.ProbeInfo, 0, len(sts))
	for _, st := range sts {
		out = append(out, &pb.ProbeInfo{
			Name:   st.Name,
			State:  probeStates[st.State],
			Source: st.Source,
			Detail: st.Detail,
		})
	}
	return out
}

// Start attaches the hub to the shared collector bus (#71) — the same bus the
// TUI can be reading, so `--serve --tui` runs one set of collectors for both.
// The handler runs inline on the bus's drain goroutine: it only maps and hands
// off to the sinks, which own their buffering, so it adds no queue and no
// second place for events to go missing. Detaches when ctx is cancelled.
// Non-blocking — returns immediately.
func (h *Hub) Start(ctx context.Context, bus *collector.Bus) {
	handler := bus.AddHandler(h.handle)
	go func() {
		<-ctx.Done()
		bus.RemoveHandler(handler)
	}()
}

// handle maps one published collector value onto the stream and broadcasts it.
func (h *Hub) handle(v interface{}) {
	// A ProcContext refreshes the cached identity before it (and every
	// subsequent event) is stamped — so the snapshot event itself carries its
	// own up-to-date uid/gid/cgroup_id.
	if pc, ok := v.(collector.ProcContext); ok {
		h.setIdent(pc)
	}
	if ev := toEvent(h.target.PID, h.buildID, v); ev != nil {
		h.stampIdent(ev)
		h.broadcast(ev)
	}
}

// setIdent updates the cached execution-context identity from a ProcContext
// snapshot (#60).
func (h *Hub) setIdent(pc collector.ProcContext) {
	h.identMu.Lock()
	h.uid, h.gid, h.cgroupID = pc.UID, pc.GID, pc.CgroupID
	h.identMu.Unlock()
}

// stampIdent writes the cached identity onto an event envelope. Values are 0
// until the first ProcContext arrives (and where /proc is unavailable).
func (h *Hub) stampIdent(ev *pb.Event) {
	h.identMu.Lock()
	ev.Uid, ev.Gid, ev.CgroupId = h.uid, h.gid, h.cgroupID
	h.identMu.Unlock()
}

// broadcast hands the event to every sink. Emit must not block (sinks own their
// buffering), so the collector drain path is never stalled by a slow consumer.
func (h *Hub) broadcast(ev *pb.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.sinks {
		s.Emit(ev)
	}
}

// AddSink registers a sink to receive subsequent events.
func (h *Hub) AddSink(s Sink) {
	h.mu.Lock()
	h.sinks[s] = struct{}{}
	h.mu.Unlock()
}

// RemoveSink stops a sink from receiving events. After it returns, broadcast no
// longer references the sink.
func (h *Hub) RemoveSink(s Sink) {
	h.mu.Lock()
	delete(h.sinks, s)
	h.mu.Unlock()
}

// subscribe registers a gRPC client (a grpcSink) with an optional category
// filter and returns it. Thin helper over AddSink used by the service.
func (h *Hub) subscribe(cats []pb.Category) *grpcSink {
	s := newGRPCSink(cats)
	h.AddSink(s)
	return s
}

func (h *Hub) unsubscribe(s *grpcSink) { h.RemoveSink(s) }

func (h *Hub) sinkCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.sinks)
}

// probeSummary is the one-line census of what is actually watching, plus a
// loud line naming every probe that was asked for and did not attach.
//
// A failure already warns at attach time, buried in whatever the collectors
// printed. The failure that matters is the one nobody read: 9 of 10 collectors
// silently dead for every capture of a service, with the resulting signatures
// indistinguishable from complete ones. Saying it once, at the moment the
// server announces itself, is the least this can do; the handshake is what
// makes it survive into the artifact.
func (h *Hub) probeSummary() []string {
	if len(h.probes) == 0 {
		return nil
	}
	byState := map[pb.ProbeState]int{}
	var failed []string
	for _, p := range h.probes {
		byState[p.GetState()]++
		if p.GetState() == pb.ProbeState_PROBE_STATE_FAILED {
			failed = append(failed, fmt.Sprintf("%s (%s)", p.GetName(), p.GetDetail()))
		}
	}
	lines := []string{fmt.Sprintf("[ptop] probes: %d active, %d failed, %d disabled, %d unsupported",
		byState[pb.ProbeState_PROBE_STATE_ACTIVE],
		byState[pb.ProbeState_PROBE_STATE_FAILED],
		byState[pb.ProbeState_PROBE_STATE_DISABLED],
		byState[pb.ProbeState_PROBE_STATE_UNSUPPORTED])}
	if len(failed) > 0 {
		lines = append(lines, fmt.Sprintf("[ptop] \u26a0 %d collector(s) asked for but NOT attached — this stream is instrumented"+
			" less than requested, and a consumer comparing it against a fully instrumented capture will"+
			" read the missing axes as behaviour that stopped: %s", len(failed), strings.Join(failed, "; ")))
	}
	return lines
}

// reportProbes prints the summary to stderr.
func (h *Hub) reportProbes() {
	for _, line := range h.probeSummary() {
		fmt.Fprintln(os.Stderr, line)
	}
}
