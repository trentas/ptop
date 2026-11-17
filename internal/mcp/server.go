// Package mcp offers ptop's capture to an agent as an MCP tool (#187):
// `ptop --mcp` speaks the Model Context Protocol on stdin and stdout and has
// one tool, capture, which is `ptop --for` under another name, plus caps,
// which is `ptop --caps`.
//
// The capture keeps every default of --for, with no argument around them: a
// window of 1s to 5 min, at most report.MaxTopN entries a list, heap off
// unless named and under a 5% overhead budget when it is, and no TLS capture,
// since the tool has no argument for it. The result is the same CaptureReport,
// so a report from the tool and one from --for read the same.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/trentas/ptop/internal/bpf"
	"github.com/trentas/ptop/internal/report"
	"github.com/trentas/ptop/internal/serve"
	"github.com/trentas/ptop/pkg/collector"
	pb "github.com/trentas/ptop/pkg/streampb"
)

// Config is what the operator fixed when launching `ptop --mcp`.
type Config struct {
	// Base is the collector config every capture starts from: --no-ebpf, the
	// symbol sources, the sampling rates, the overhead budget. A subsystem its
	// Disable names cannot be asked for.
	Base collector.SetConfig
	// BudgetGiven says --overhead-budget was on the command line. Without it,
	// a capture that names heap runs under serve.CaptureHeapBudgetPct, as
	// --for does.
	BudgetGiven bool
	// Scope is which targets an agent may name.
	Scope Scope
	// Build identifies this ptop, in the report and in the MCP handshake.
	Build serve.PtopBuild
	// StartFeed starts the collectors of one capture. The server stops the
	// feed when the window closes.
	StartFeed func(ctx context.Context, cfg collector.SetConfig) (*collector.Feed, serve.StackResolver)
	// Caps returns the `ptop --caps` inventory. nil reads this ptop's own.
	Caps func() string
}

// Run serves MCP on in and out until the client goes away or ctx ends.
func Run(ctx context.Context, cfg Config, in io.ReadCloser, out io.WriteCloser) error {
	srv, err := newServer(cfg)
	if err != nil {
		return err
	}
	err = srv.Run(ctx, &sdk.IOTransport{Reader: in, Writer: out})
	if ctx.Err() != nil || errors.Is(err, io.EOF) {
		return nil // the client closed stdin, or ptop was told to stop
	}
	return err
}

const instructions = `ptop measures one process, or a cgroup subtree, with eBPF on Linux (and with libproc on macOS, with fewer axes).

capture runs one fixed window and returns a CaptureReport as JSON, the report ` + "`ptop --for`" + ` prints: CPU, the functions the CPU time went to, threads, memory, heap, syscalls, file and network I/O, locks, signals, process lifecycle, and runtime pauses.

How to read it:
- Read target.probes first. A section is absent when its probe did not run, and the probe set says why. In a section that is present, a zero is a measurement.
- A total is an axis's last reading in the window less its first.
- Every list is cut to top entries and says what it left out.

caps lists the capabilities this ptop holds and which probes they let it run, and which targets this server may capture.`

// server is one ptop --mcp: the tools, and the capture running, if any.
type server struct {
	cfg Config

	mu  sync.Mutex
	cur *running // the capture running; nil when idle. mu.
}

// running is a capture in progress, for the busy error.
type running struct {
	target  string
	window  time.Duration
	started time.Time // when the window opened; zero while the probes attach
}

func newServer(cfg Config) (*sdk.Server, error) {
	if cfg.StartFeed == nil {
		return nil, errors.New("mcp: Config.StartFeed is nil")
	}
	s := &server{cfg: cfg}
	schema, err := captureSchema(cfg.Base.Disable)
	if err != nil {
		return nil, err
	}

	srv := sdk.NewServer(&sdk.Implementation{Name: "ptop", Version: cfg.Build.Version},
		&sdk.ServerOptions{Instructions: instructions})
	sdk.AddTool(srv, &sdk.Tool{
		Name:  "capture",
		Title: "Capture one window over a process",
		Description: fmt.Sprintf(`Capture one fixed window over a process (pid) or a cgroup subtree (cgroup), then return a CaptureReport as JSON: the report `+"`ptop --for`"+` prints.

The window opens once every probe has attached, which takes a second or two, and then runs for seconds. It ends early if the target exits (window.end says so).

Heap is off unless probes names it. When it runs, it is detached if its estimated cost stays above %g%% of the target's CPU, and probe_changes records it.

One capture runs at a time.

This server captures %s.`, serve.CaptureHeapBudgetPct, cfg.Scope),
		InputSchema: schema,
		Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(false)},
	}, s.capture)
	sdk.AddTool(srv, &sdk.Tool{
		Name:        "caps",
		Title:       "What this ptop can capture",
		Description: "Return the `ptop --caps` inventory: the capabilities this ptop holds, the reads it can make, which probes those let it run and why the others will fail. Also returns which targets this server may capture. Call it before a capture to learn why an axis would be missing.",
		InputSchema: &jsonschema.Schema{Type: "object"},
		Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: ptr(false)},
	}, s.caps)
	return srv, nil
}

func ptr[T any](v T) *T { return &v }

// captureArgs are the capture tool's arguments.
type captureArgs struct {
	PID     int      `json:"pid,omitempty"`
	Cgroup  string   `json:"cgroup,omitempty"`
	Seconds int      `json:"seconds"`
	Probes  []string `json:"probes,omitempty"`
	Top     int      `json:"top,omitempty"`
}

// captureSchema is the input schema of capture, with the bounds of --for, so
// an agent learns them from the schema before it hits one. The probes enum
// leaves out tls, which a report never carries, and what the operator
// disabled.
func captureSchema(disabled map[string]bool) (*jsonschema.Schema, error) {
	sc, err := jsonschema.For[captureArgs](nil)
	if err != nil {
		return nil, fmt.Errorf("mcp: capture schema: %w", err)
	}
	var probes []any
	for _, n := range collector.SubsystemNames() {
		if n != collector.SubsystemTLS && !disabled[n] {
			probes = append(probes, n)
		}
	}
	p := sc.Properties
	p["pid"].Description = "The process to capture. Pass pid or cgroup, not both."
	p["pid"].Minimum = ptr(1.0)
	p["cgroup"].Description = "A cgroup subtree to capture instead of one process: a cgroup v2 path or a container id. Linux with eBPF only."
	p["seconds"].Description = "How long the window runs once the probes have attached."
	p["seconds"].Minimum = ptr(serve.MinCaptureWindow.Seconds())
	p["seconds"].Maximum = ptr(serve.MaxCaptureWindow.Seconds())
	p["probes"].Description = "The only subsystems to run. Without it, every subsystem runs but heap, whose probe fires on every allocation."
	p["probes"].Items.Enum = probes
	p["probes"].MinItems = ptr(1)
	p["probes"].UniqueItems = true
	p["top"].Description = "The most entries any list in the report carries."
	p["top"].Minimum = ptr(1.0)
	p["top"].Maximum = ptr(float64(report.MaxTopN))
	p["top"].Default = json.RawMessage(fmt.Sprint(report.DefaultTopN))
	return sc, nil
}

// reportJSON renders a report as --for does: EmitDefaultValues, because a
// zero in a report is a measurement. Compact, because it goes into a context
// window.
var reportJSON = protojson.MarshalOptions{EmitDefaultValues: true}

func (s *server) capture(ctx context.Context, req *sdk.CallToolRequest, a captureArgs) (*sdk.CallToolResult, any, error) {
	window := time.Duration(a.Seconds) * time.Second
	if window < serve.MinCaptureWindow || window > serve.MaxCaptureWindow {
		return nil, nil, fmt.Errorf("seconds %d: a window runs from %v to %v", a.Seconds, serve.MinCaptureWindow, serve.MaxCaptureWindow)
	}
	top := a.Top
	if top == 0 {
		top = report.DefaultTopN
	}
	if top < 1 || top > report.MaxTopN {
		return nil, nil, fmt.Errorf("top %d: from 1 to %d", a.Top, report.MaxTopN)
	}
	disable, err := s.disable(a.Probes)
	if err != nil {
		return nil, nil, err
	}
	target, err := s.target(a)
	if err != nil {
		return nil, nil, err
	}
	if err := s.acquire(target, window); err != nil {
		return nil, nil, err
	}
	defer s.release()

	cfg := s.setConfig(target, disable)

	// Everything this capture starts ends with it: the bus drain, the pid
	// watcher, the progress loop.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	started := make(chan struct{})
	stopProgress := s.progress(ctx, req, target, window, started)
	defer stopProgress()

	feed, resolver := s.cfg.StartFeed(ctx, cfg)
	defer feed.Stop()
	opts := serve.CaptureOptions{
		For: window, TopN: top, ListCap: report.CollectorListCap,
		Build: s.cfg.Build, Started: started,
	}
	if !target.IsCgroup() {
		opts.Exited = serve.WatchPID(ctx, target.PID)
	}
	r, err := serve.Capture(ctx, target, feed, resolver, opts)
	if err != nil {
		return nil, nil, err
	}
	if ctx.Err() != nil {
		// The client cancelled, and ignores whatever answers the call now
		// (MCP's cancellation rule). The probes are released all the same.
		return nil, nil, errors.New("capture cancelled")
	}
	res, err := reportResult(r)
	return res, nil, err
}

// setConfig is the collector config of one capture: the operator's, with the
// target, what runs, and the list cap and heap budget of --for.
func (s *server) setConfig(t serve.Target, disable map[string]bool) collector.SetConfig {
	cfg := s.cfg.Base
	cfg.PID, cfg.Cgroup = t.PID, t.CgroupPath
	cfg.Disable = disable
	cfg.ListCap = report.CollectorListCap
	cfg.TLS, cfg.TLSMaxBytes = false, 0
	if !disable[collector.SubsystemHeap] && !s.cfg.BudgetGiven {
		cfg.OverheadBudgetPct = serve.CaptureHeapBudgetPct
	}
	return cfg
}

// reportResult is the report as the tool's result: the JSON as text, and the
// same object as structured content. A window in which no probe was active is
// an error that carries the report, whose probe set says why.
func reportResult(r *pb.CaptureReport) (*sdk.CallToolResult, error) {
	b, err := reportJSON.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("report: %w", err)
	}
	res := &sdk.CallToolResult{
		Content:           []sdk.Content{&sdk.TextContent{Text: string(b)}},
		StructuredContent: json.RawMessage(b),
	}
	if !serve.ProbesActive(r) {
		res.IsError = true
		res.Content = append([]sdk.Content{&sdk.TextContent{
			Text: "No probe was active, so the window measured nothing. target.probes in the report says why each one is not active.",
		}}, res.Content...)
	}
	return res, nil
}

// disable is what a capture switches off: what --for would, less nothing the
// operator disabled.
func (s *server) disable(probes []string) (map[string]bool, error) {
	op := s.cfg.Base.Disable
	if len(probes) == 0 {
		return serve.CaptureDisable("", op)
	}
	for _, p := range probes {
		if op[strings.ToLower(strings.TrimSpace(p))] {
			return nil, fmt.Errorf("probes: %s is disabled on this server (--disable)", p)
		}
		if strings.EqualFold(strings.TrimSpace(p), collector.SubsystemTLS) {
			return nil, errors.New("probes: tls is never captured here: a report does not carry the target's TLS traffic")
		}
	}
	d, err := serve.CaptureDisable(strings.Join(probes, ","), nil)
	if err != nil {
		return nil, fmt.Errorf("probes: %w", err)
	}
	for name := range op {
		d[name] = true
	}
	return d, nil
}

// target resolves the target the arguments name and checks it against the
// scope.
func (s *server) target(a captureArgs) (serve.Target, error) {
	switch {
	case a.PID != 0 && a.Cgroup != "":
		return serve.Target{}, errors.New("pid and cgroup name different targets: pass one")
	case a.PID < 0:
		return serve.Target{}, fmt.Errorf("pid %d is not a valid pid", a.PID)
	case a.PID > 0:
		if errors.Is(syscall.Kill(a.PID, 0), syscall.ESRCH) {
			return serve.Target{}, fmt.Errorf("pid %d: no such process", a.PID)
		}
		if err := s.cfg.Scope.AllowPID(a.PID); err != nil {
			return serve.Target{}, err
		}
		return serve.TargetPID(a.PID), nil
	case a.Cgroup != "":
		if s.cfg.Base.NoEBPF {
			return serve.Target{}, errors.New("cgroup: needs eBPF, and this server runs with --no-ebpf")
		}
		p, id, err := bpf.ResolveCgroupSpec(a.Cgroup)
		if err != nil {
			return serve.Target{}, fmt.Errorf("cgroup %s: %w", a.Cgroup, err)
		}
		if err := s.cfg.Scope.AllowCgroup(p); err != nil {
			return serve.Target{}, err
		}
		return serve.TargetCgroup(p, id), nil
	}
	return serve.Target{}, errors.New("name a target: pid or cgroup")
}

// acquire takes the one capture slot, or says what holds it. Two captures at
// once would load the eBPF set twice on the host.
func (s *server) acquire(t serve.Target, window time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.cur; c != nil {
		state := "is attaching its probes"
		if !c.started.IsZero() {
			left := c.window - time.Since(c.started)
			state = fmt.Sprintf("has %v left", max(left, 0).Round(time.Second))
		}
		return fmt.Errorf("busy: ptop runs one capture at a time, and a %v capture of %s %s", c.window, c.target, state)
	}
	s.cur = &running{target: t.String(), window: window}
	return nil
}

func (s *server) release() {
	s.mu.Lock()
	s.cur = nil
	s.mu.Unlock()
}

// progress tells the client how the capture goes, once a second, when the
// call carried a progress token. A five-minute call with nothing on the wire
// looks hung, and a client times a request out after 60s by default. The
// returned func stops it, and returns once nothing more will be sent.
func (s *server) progress(ctx context.Context, req *sdk.CallToolRequest, t serve.Target, window time.Duration, started <-chan struct{}) func() {
	token := req.Params.GetProgressToken()
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		notify := func(p float64, msg string) {
			if token == nil {
				return
			}
			_ = req.Session.NotifyProgress(ctx, &sdk.ProgressNotificationParams{
				ProgressToken: token, Progress: p, Total: window.Seconds(), Message: msg,
			})
		}
		notify(0, fmt.Sprintf("attaching probes to %s", t))
		select {
		case <-started:
		case <-done:
			return
		case <-ctx.Done():
			return
		}
		opened := time.Now()
		s.mu.Lock()
		if s.cur != nil {
			s.cur.started = opened
		}
		s.mu.Unlock()

		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				el := min(time.Since(opened), window)
				notify(el.Seconds(), fmt.Sprintf("capturing %s: %v of %v", t, el.Round(time.Second), window))
			case <-done:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	return func() {
		close(done)
		wg.Wait()
	}
}

func (s *server) caps(context.Context, *sdk.CallToolRequest, any) (*sdk.CallToolResult, any, error) {
	inv := ""
	if s.cfg.Caps != nil {
		inv = s.cfg.Caps()
	} else {
		inv = bpf.GetCapStatus().CapReport()
	}
	var b strings.Builder
	b.WriteString(strings.TrimRight(inv, "\n"))
	fmt.Fprintf(&b, "\n\nScope: this server captures %s.\n", s.cfg.Scope)
	if op := s.cfg.Base.Disable; len(op) > 0 {
		names := make([]string, 0, len(op))
		for n := range op {
			names = append(names, n)
		}
		slices.Sort(names)
		fmt.Fprintf(&b, "Disabled by the operator (--disable), so never run here: %s.\n", strings.Join(names, ", "))
	}
	if s.cfg.Base.NoEBPF {
		b.WriteString("This server runs with --no-ebpf: every capture reads /proc only.\n")
	}
	return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: b.String()}}}, nil, nil
}
