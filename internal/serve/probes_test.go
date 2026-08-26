package serve

import (
	"os"
	"strings"
	"testing"

	"github.com/trentas/ptop/pkg/collector"
	pb "github.com/trentas/ptop/pkg/streampb"
)

// The handshake carries the probe set alongside the scope (#112). A subscriber
// that only sees events cannot tell a probe that never attached from a target
// that never did the thing; TargetInfo is where that gets said.
func TestHandshakeReportsTheProbeSet(t *testing.T) {
	set := collector.NewSet(collector.SetConfig{PID: os.Getpid(), NoEBPF: true})
	defer set.Stop()

	ti := NewHub(TargetPID(os.Getpid()), "", set).targetInfo()
	if len(ti.GetProbes()) == 0 {
		t.Fatal("handshake carried no probe set")
	}

	seen := map[string]*pb.ProbeInfo{}
	for _, p := range ti.GetProbes() {
		if p.GetState() == pb.ProbeState_PROBE_STATE_UNSPECIFIED {
			t.Errorf("%s reported UNSPECIFIED — a state the wire reserves for a server that does not know", p.GetName())
		}
		seen[p.GetName()] = p
	}

	// --no-ebpf removes the heap probe rather than degrading it, and the
	// handshake must say disabled — the case that turns a no-op deploy into a
	// −100% regression on every heap call site when it goes unrecorded.
	heap, ok := seen[collector.SubsystemHeap]
	if !ok {
		t.Fatalf("heap absent from the handshake: %v", seen)
	}
	if heap.GetState() != pb.ProbeState_PROBE_STATE_DISABLED {
		t.Errorf("heap state = %v, want DISABLED", heap.GetState())
	}
	if heap.GetDetail() == "" {
		t.Error("a disabled probe must carry why")
	}
}

// A hub built without a Set reports no probes at all. Empty means "this server
// does not say", which is what an older ptop looks like on the wire — never
// "every probe ran".
func TestHandshakeWithoutASetCarriesNoProbes(t *testing.T) {
	if got := NewHub(TargetPID(7), "", nil).targetInfo().GetProbes(); got != nil {
		t.Errorf("probes = %v, want nil for a hub with no collectors", got)
	}
}

// Cgroup mode gets the probe set too: its structural omissions are exactly the
// ones a consumer would otherwise read as the subtree having gone quiet.
func TestCgroupHandshakeReportsTheProbeSet(t *testing.T) {
	set := collector.NewSet(collector.SetConfig{Cgroup: "/sys/fs/cgroup/nonexistent.scope"})
	defer set.Stop()

	ti := NewHub(TargetCgroup("/sys/fs/cgroup/nonexistent.scope", 7), "", set).targetInfo()
	if ti.GetMode() != pb.TargetMode_TARGET_MODE_CGROUP {
		t.Fatalf("mode = %v, want CGROUP", ti.GetMode())
	}
	for _, p := range ti.GetProbes() {
		if p.GetName() == collector.SubsystemHeap {
			if p.GetState() != pb.ProbeState_PROBE_STATE_UNSUPPORTED {
				t.Errorf("heap state = %v, want UNSUPPORTED in cgroup scope", p.GetState())
			}
			return
		}
	}
	t.Fatalf("heap absent from the cgroup handshake: %v", ti.GetProbes())
}

// A probe that was asked for and did not attach must be loud at the moment the
// server announces itself, not only in whatever the collector printed while
// attaching. The measured cost of it being quiet: 9 of 10 collectors dead on
// every capture of a service, with nothing downstream able to tell.
func TestProbeSummaryNamesEveryFailedCollector(t *testing.T) {
	h := &Hub{probes: []*pb.ProbeInfo{
		{Name: "cpu", State: pb.ProbeState_PROBE_STATE_ACTIVE, Source: "eBPF"},
		{Name: "heap", State: pb.ProbeState_PROBE_STATE_DISABLED, Detail: "--disable heap"},
		{Name: "syscalls", State: pb.ProbeState_PROBE_STATE_FAILED, Detail: "open tracefs: no such file or directory"},
	}}
	lines := h.probeSummary()
	if len(lines) != 2 {
		t.Fatalf("expected a census and a warning, got %q", lines)
	}
	if !strings.Contains(lines[0], "1 active") || !strings.Contains(lines[0], "1 failed") || !strings.Contains(lines[0], "1 disabled") {
		t.Errorf("census does not count the states: %q", lines[0])
	}
	if !strings.Contains(lines[1], "syscalls") || !strings.Contains(lines[1], "no such file or directory") {
		t.Errorf("warning does not name the failure: %q", lines[1])
	}
	if strings.Contains(lines[1], "heap") {
		t.Errorf("a disabled probe is not a failure and must not be warned about: %q", lines[1])
	}
}

// Nothing is printed when the server has no probe set to report — silence is
// what an older server says, and inventing a census for it would be a claim.
func TestProbeSummarySilentWithoutAProbeSet(t *testing.T) {
	if lines := (&Hub{}).probeSummary(); lines != nil {
		t.Errorf("expected no output, got %q", lines)
	}
}
