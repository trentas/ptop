package mcp

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/trentas/ptop/internal/report"
	"github.com/trentas/ptop/internal/serve"
	"github.com/trentas/ptop/pkg/collector"
	pb "github.com/trentas/ptop/pkg/streampb"
)

// fakeCollector publishes nothing: a feed of it reaches the report as a window
// with no probe set.
type fakeCollector struct{ ch chan interface{} }

func (f *fakeCollector) Start(int) error               { return nil }
func (f *fakeCollector) Stop()                         {}
func (f *fakeCollector) Subscribe() <-chan interface{} { return f.ch }

// feeds records what the server asked of its feed factory.
type feeds struct {
	mu      sync.Mutex
	cfgs    []collector.SetConfig
	ctxs    []context.Context
	started chan struct{} // one send per feed started
	real    bool          // a real --no-ebpf Set on the target, not a fake
}

func newFeeds() *feeds { return &feeds{started: make(chan struct{}, 16)} }

func (f *feeds) start(ctx context.Context, cfg collector.SetConfig) (*collector.Feed, serve.StackResolver) {
	f.mu.Lock()
	f.cfgs = append(f.cfgs, cfg)
	f.ctxs = append(f.ctxs, ctx)
	f.mu.Unlock()
	f.started <- struct{}{}
	if f.real {
		cfg.NoEBPF = true
		return collector.StartFeed(ctx, cfg), nil
	}
	return &collector.Feed{Bus: collector.StartBus(ctx, []collector.Collector{&fakeCollector{ch: make(chan interface{}, 1)}})}, nil
}

func (f *feeds) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.cfgs)
}

// session runs Run over two pipes, the way `ptop --mcp` runs it over stdio,
// and connects a client to it.
type session struct {
	cs       *sdk.ClientSession
	progress chan *sdk.ProgressNotificationParams
	done     chan error // Run's return
}

func startSession(t *testing.T, cfg Config) *session {
	t.Helper()
	clientIn, serverOut := io.Pipe()
	serverIn, clientOut := io.Pipe()
	s := &session{progress: make(chan *sdk.ProgressNotificationParams, 64), done: make(chan error, 1)}
	go func() { s.done <- Run(context.Background(), cfg, serverIn, serverOut) }()

	client := sdk.NewClient(&sdk.Implementation{Name: "test", Version: "0"}, &sdk.ClientOptions{
		ProgressNotificationHandler: func(_ context.Context, r *sdk.ProgressNotificationClientRequest) {
			s.progress <- r.Params
		},
	})
	cs, err := client.Connect(context.Background(), &sdk.IOTransport{Reader: clientIn, Writer: clientOut}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	s.cs = cs
	t.Cleanup(func() {
		cs.Close()
		select {
		case <-s.done:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return once the client went away")
		}
	})
	return s
}

func (s *session) capture(t *testing.T, args map[string]any) *sdk.CallToolResult {
	t.Helper()
	res, err := s.cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "capture", Arguments: args})
	if err != nil {
		t.Fatalf("capture(%v): protocol error %v, want a tool result", args, err)
	}
	return res
}

func text(r *sdk.CallToolResult) string {
	var parts []string
	for _, c := range r.Content {
		if tc, ok := c.(*sdk.TextContent); ok {
			parts = append(parts, tc.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// lastReport parses the report, the last text block of a result.
func lastReport(t *testing.T, r *sdk.CallToolResult) *pb.CaptureReport {
	t.Helper()
	tc, ok := r.Content[len(r.Content)-1].(*sdk.TextContent)
	if !ok {
		t.Fatalf("last content is %T, want text", r.Content[len(r.Content)-1])
	}
	var rep pb.CaptureReport
	if err := protojson.Unmarshal([]byte(tc.Text), &rep); err != nil {
		t.Fatalf("the text is not a CaptureReport: %v", err)
	}
	return &rep
}

func anyScope() Scope { return Scope{Any: true} }

// The schema carries the bounds of --for, so an agent learns them before it
// hits one, and the tool says what this server may capture.
func TestToolsList(t *testing.T) {
	cfg := Config{Scope: anyScope(), StartFeed: newFeeds().start,
		Base: collector.SetConfig{Disable: map[string]bool{collector.SubsystemNetwork: true}}}
	s := startSession(t, cfg)
	res, err := s.cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tools := map[string]*sdk.Tool{}
	for _, tl := range res.Tools {
		tools[tl.Name] = tl
	}
	if len(tools) != 2 || tools["capture"] == nil || tools["caps"] == nil {
		t.Fatalf("tools = %v, want capture and caps", res.Tools)
	}
	c := tools["capture"]
	if !strings.Contains(c.Description, "any process on this host") {
		t.Errorf("capture's description does not state the scope:\n%s", c.Description)
	}
	b, _ := json.Marshal(c.InputSchema)
	var sc struct {
		Required   []string
		Properties map[string]struct {
			Minimum, Maximum *float64
			Default          json.RawMessage
			Items            *struct{ Enum []string }
		}
	}
	if err := json.Unmarshal(b, &sc); err != nil {
		t.Fatal(err)
	}
	p := sc.Properties
	if len(sc.Required) != 1 || sc.Required[0] != "seconds" {
		t.Errorf("required = %v, want [seconds]", sc.Required)
	}
	if mn, mx := p["seconds"].Minimum, p["seconds"].Maximum; mn == nil || mx == nil || *mn != 1 || *mx != 300 {
		t.Errorf("seconds bounds = %v..%v, want 1..300 (the --for window)", mn, mx)
	}
	if mx := p["top"].Maximum; mx == nil || *mx != report.MaxTopN || string(p["top"].Default) != "10" {
		t.Errorf("top = max %v default %s, want max %d default %d", mx, p["top"].Default, report.MaxTopN, report.DefaultTopN)
	}
	enum := strings.Join(p["probes"].Items.Enum, ",")
	if strings.Contains(enum, "tls") || strings.Contains(enum, "network") || !strings.Contains(enum, "cpu") {
		t.Errorf("probes enum = %s, want no tls, nothing the operator disabled (network), and cpu", enum)
	}
}

// The tool's report is --for's: the same CaptureReport, as text and as
// structured content, over a real collector set.
func TestCaptureReturnsTheReport(t *testing.T) {
	t.Parallel()
	f := newFeeds()
	f.real = true
	s := startSession(t, Config{Scope: anyScope(), StartFeed: f.start})
	res := s.capture(t, map[string]any{"pid": os.Getpid(), "seconds": 1, "probes": []string{"cpu"}})
	if res.IsError {
		t.Fatalf("capture failed: %s", text(res))
	}
	rep := lastReport(t, res)
	if w := rep.GetWindow(); w.GetEnd() != pb.WindowEnd_WINDOW_END_COMPLETE || w.GetRequestedMs() != 1000 || w.GetTopN() != report.DefaultTopN {
		t.Errorf("window = %v, want COMPLETE, 1000ms, top %d", w, report.DefaultTopN)
	}
	if rep.GetTarget().GetPid() != int32(os.Getpid()) {
		t.Errorf("target pid = %d, want %d", rep.GetTarget().GetPid(), os.Getpid())
	}
	if !serve.ProbesActive(rep) {
		t.Errorf("no probe active over a real feed: %v", rep.GetTarget().GetProbes())
	}

	// The structured content is the same report.
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var structured pb.CaptureReport
	if err := protojson.Unmarshal(b, &structured); err != nil {
		t.Fatalf("structuredContent is not a CaptureReport: %v", err)
	}
	if !proto.Equal(&structured, rep) {
		t.Error("structuredContent and the text block are different reports")
	}
	// EmitDefaultValues: a zero is a measurement and must be on the wire.
	if !strings.Contains(text(res), `"probeChanges":[]`) {
		t.Errorf("zeros were dropped from the report: %s", text(res))
	}

	cfg := f.cfgs[0]
	if cfg.PID != os.Getpid() || cfg.ListCap != report.CollectorListCap || cfg.Disable[collector.SubsystemCPU] || !cfg.Disable[collector.SubsystemIO] {
		t.Errorf("feed config = pid %d, list cap %d, disable %v; want this pid, %d, only cpu running",
			cfg.PID, cfg.ListCap, cfg.Disable, report.CollectorListCap)
	}
}

// What a capture runs is what --for would, less what the operator disabled.
func TestCaptureConfigMatchesFor(t *testing.T) {
	op := map[string]bool{collector.SubsystemIO: true}
	s := &server{cfg: Config{Base: collector.SetConfig{Disable: op, TLS: true, TLSMaxBytes: 64, CPUProfHz: 250}}}
	target := serve.TargetPID(4242)

	d, err := s.disable(nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := s.setConfig(target, d)
	if !cfg.Disable[collector.SubsystemHeap] || !cfg.Disable[collector.SubsystemIO] || len(cfg.Disable) != 2 {
		t.Errorf("no probes: disable = %v, want heap and the operator's io", cfg.Disable)
	}
	if cfg.OverheadBudgetPct != 0 {
		t.Errorf("heap off: budget = %v, want none", cfg.OverheadBudgetPct)
	}
	if cfg.TLS || cfg.TLSMaxBytes != 0 {
		t.Error("a capture ran with TLS capture on")
	}
	if cfg.CPUProfHz != 250 || cfg.PID != 4242 || cfg.ListCap != report.CollectorListCap {
		t.Errorf("cfg = %+v, want the operator's base with the target and the list cap", cfg)
	}

	d, err = s.disable([]string{"heap", "cpu"})
	if err != nil {
		t.Fatal(err)
	}
	cfg = s.setConfig(target, d)
	if cfg.Disable[collector.SubsystemHeap] || cfg.Disable[collector.SubsystemCPU] || !cfg.Disable[collector.SubsystemIO] {
		t.Errorf("probes heap,cpu: disable = %v", cfg.Disable)
	}
	if cfg.OverheadBudgetPct != serve.CaptureHeapBudgetPct {
		t.Errorf("heap named: budget = %v, want %v", cfg.OverheadBudgetPct, serve.CaptureHeapBudgetPct)
	}

	// The operator's budget, when given, is the one that holds.
	s.cfg.BudgetGiven, s.cfg.Base.OverheadBudgetPct = true, 2
	if cfg = s.setConfig(target, d); cfg.OverheadBudgetPct != 2 {
		t.Errorf("--overhead-budget 2: budget = %v", cfg.OverheadBudgetPct)
	}

	if _, err := s.disable([]string{"io"}); err == nil || !strings.Contains(err.Error(), "--disable") {
		t.Errorf("a probe the operator disabled = %v, want refused", err)
	}
	if _, err := s.disable([]string{"tls"}); err == nil {
		t.Error("tls was accepted")
	}
}

// A bad argument is a tool error that names it, and starts nothing.
func TestCaptureRefusals(t *testing.T) {
	f := newFeeds()
	other := uint32(os.Getuid()) + 1
	scope := Scope{UIDs: []uint32{uint32(os.Getuid())},
		uidsOf: func(pid int) ([]uint32, error) {
			if pid == os.Getpid() {
				return []uint32{other, other, other, other}, nil
			}
			return processUIDs(pid)
		}}
	s := startSession(t, Config{Scope: scope, StartFeed: f.start})
	self := os.Getpid()
	cases := []struct {
		name string
		args map[string]any
		want string
	}{
		{"no target", map[string]any{"seconds": 1}, "pid or cgroup"},
		{"two targets", map[string]any{"pid": self, "cgroup": "/x", "seconds": 1}, "pass one"},
		{"no seconds", map[string]any{"pid": self}, "seconds"},
		{"too short", map[string]any{"pid": self, "seconds": 0}, "seconds"},
		{"too long", map[string]any{"pid": self, "seconds": 301}, "seconds"},
		{"top too high", map[string]any{"pid": self, "seconds": 1, "top": 51}, "top"},
		{"unknown probe", map[string]any{"pid": self, "seconds": 1, "probes": []string{"nonsense"}}, "probes"},
		{"tls", map[string]any{"pid": self, "seconds": 1, "probes": []string{"tls"}}, "probes"},
		{"no such pid", map[string]any{"pid": 1 << 30, "seconds": 1}, "no such process"},
		{"out of scope", map[string]any{"pid": self, "seconds": 1}, "outside this server's scope"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := s.capture(t, c.args)
			if !res.IsError || !strings.Contains(text(res), c.want) {
				t.Errorf("= error %v %q, want an error containing %q", res.IsError, text(res), c.want)
			}
		})
	}
	if n := f.count(); n != 0 {
		t.Errorf("%d feeds started for refused captures", n)
	}
}

// A window in which no probe was active is an error, and carries the report
// whose probe set says why.
func TestCaptureNoProbeIsError(t *testing.T) {
	t.Parallel()
	s := startSession(t, Config{Scope: anyScope(), StartFeed: newFeeds().start})
	res := s.capture(t, map[string]any{"pid": os.Getpid(), "seconds": 1})
	if !res.IsError {
		t.Fatalf("no probe active, and the result is not an error: %s", text(res))
	}
	if !strings.Contains(text(res), "No probe was active") {
		t.Errorf("the error does not say why: %s", text(res))
	}
	if lastReport(t, res).GetWindow().GetEnd() != pb.WindowEnd_WINDOW_END_COMPLETE {
		t.Error("the report did not come with the error")
	}
}

// One capture at a time: the second is refused at once, and says what holds
// the slot. The slot is free again afterwards.
func TestCaptureBusy(t *testing.T) {
	t.Parallel()
	f := newFeeds()
	s := startSession(t, Config{Scope: anyScope(), StartFeed: f.start})
	first := make(chan *sdk.CallToolResult, 1)
	go func() {
		res, _ := s.cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "capture",
			Arguments: map[string]any{"pid": os.Getpid(), "seconds": 2}})
		first <- res
	}()
	<-f.started

	res := s.capture(t, map[string]any{"pid": os.Getpid(), "seconds": 1})
	if !res.IsError || !strings.Contains(text(res), "busy") || !strings.Contains(text(res), "pid") {
		t.Errorf("second capture = error %v %q, want busy naming the first", res.IsError, text(res))
	}
	if r := <-first; r == nil || !strings.Contains(text(r), `"end":"WINDOW_END_COMPLETE"`) {
		t.Errorf("the first capture did not complete: %v", r)
	}
	if res := s.capture(t, map[string]any{"pid": os.Getpid(), "seconds": 1}); strings.Contains(text(res), "busy") {
		t.Errorf("the slot was not released: %s", text(res))
	}
	if n := f.count(); n != 2 {
		t.Errorf("%d feeds started, want 2: the busy call must start none", n)
	}
}

// A cancelled call stops the probes and frees the slot.
func TestCaptureCancelled(t *testing.T) {
	t.Parallel()
	f := newFeeds()
	s := startSession(t, Config{Scope: anyScope(), StartFeed: f.start})
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := s.cs.CallTool(ctx, &sdk.CallToolParams{Name: "capture",
			Arguments: map[string]any{"pid": os.Getpid(), "seconds": 300}})
		errc <- err
	}()
	<-f.started
	cancel()
	if err := <-errc; err == nil {
		t.Error("a cancelled call returned a result")
	}
	select {
	case <-f.ctxs[0].Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the cancelled capture's feed is still running")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		res := s.capture(t, map[string]any{"pid": os.Getpid(), "seconds": 1})
		if !strings.Contains(text(res), "busy") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the slot was never released after a cancel")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// With a progress token the client hears from the capture every second, with
// a total and a value that only grows.
func TestCaptureProgress(t *testing.T) {
	t.Parallel()
	s := startSession(t, Config{Scope: anyScope(), StartFeed: newFeeds().start})
	params := &sdk.CallToolParams{Name: "capture", Arguments: map[string]any{"pid": os.Getpid(), "seconds": 2}}
	params.SetProgressToken("tok")
	if _, err := s.cs.CallTool(context.Background(), params); err != nil {
		t.Fatal(err)
	}
	var got []*sdk.ProgressNotificationParams
	for done := false; !done; {
		select {
		case p := <-s.progress:
			got = append(got, p)
		case <-time.After(200 * time.Millisecond):
			done = true
		}
	}
	if len(got) < 2 {
		t.Fatalf("%d progress notifications for a 2s window, want the start and at least one tick", len(got))
	}
	if !strings.Contains(got[0].Message, "attaching") || got[0].Progress != 0 {
		t.Errorf("first = %+v, want progress 0 while attaching", got[0])
	}
	for i, p := range got {
		if p.ProgressToken != "tok" || p.Total != 2 {
			t.Errorf("#%d = token %v total %v, want tok and 2", i, p.ProgressToken, p.Total)
		}
		if i > 0 && p.Progress <= got[i-1].Progress {
			t.Errorf("#%d progress %v after %v: it must increase", i, p.Progress, got[i-1].Progress)
		}
	}
}

func TestCapsTool(t *testing.T) {
	cfg := Config{
		Scope: anyScope(), StartFeed: newFeeds().start,
		Base: collector.SetConfig{NoEBPF: true, Disable: map[string]bool{collector.SubsystemHeap: true}},
		Caps: func() string { return "INVENTORY\n" },
	}
	s := startSession(t, cfg)
	res, err := s.cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "caps"})
	if err != nil || res.IsError {
		t.Fatalf("caps = %v, %v", err, res)
	}
	out := text(res)
	for _, want := range []string{"INVENTORY", "this server captures any process on this host", "(--disable), so never run here: heap", "--no-ebpf"} {
		if !strings.Contains(out, want) {
			t.Errorf("caps does not say %q:\n%s", want, out)
		}
	}
}

// Run serves until the client closes its end, then returns cleanly.
func TestRunEndsWhenTheClientCloses(t *testing.T) {
	var started atomic.Bool
	s := startSession(t, Config{Scope: anyScope(), StartFeed: func(ctx context.Context, cfg collector.SetConfig) (*collector.Feed, serve.StackResolver) {
		started.Store(true)
		return newFeeds().start(ctx, cfg)
	}})
	s.cs.Close()
	select {
	case err := <-s.done:
		if err != nil {
			t.Errorf("Run = %v, want nil once the client is gone", err)
		}
		s.done <- err // for the cleanup
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
}
