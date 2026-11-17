package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	pb "github.com/trentas/ptop/pkg/streampb"
)

func TestCheckPIDExistsSelf(t *testing.T) {
	if err := checkPIDExists(os.Getpid()); err != nil {
		t.Fatalf("checkPIDExists(self) = %v, want nil", err)
	}
}

func TestCheckPIDExistsPID1(t *testing.T) {
	// PID 1 (init/launchd) always exists and is owned by root, so this
	// exercises the EPERM branch whenever the test doesn't run as root.
	if err := checkPIDExists(1); err != nil {
		t.Fatalf("checkPIDExists(1) = %v, want nil", err)
	}
}

func TestCheckPIDExistsGone(t *testing.T) {
	// Spawn a short-lived process and reap it; its PID is then free. PID
	// reuse inside this window is theoretically possible but negligible.
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatalf("spawning `true`: %v", err)
	}
	err := checkPIDExists(cmd.Process.Pid)
	if err == nil {
		t.Fatalf("checkPIDExists(%d) = nil, want error for reaped pid", cmd.Process.Pid)
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("checkPIDExists(%d) = %q, want a 'does not exist' error", cmd.Process.Pid, err)
	}
}

func TestCheckTargetFlags(t *testing.T) {
	const sock = "unix:///run/ptop.sock"
	cases := []struct {
		name       string
		pid        int
		cgroup     string
		serveAddr  string
		noEBPF     bool
		withTUI    bool
		capture    bool   // --for (#156)
		wantErrHas string // "" = must be accepted
	}{
		{name: "pid alone", pid: 42},
		{name: "pid with serve", pid: 42, serveAddr: sock},
		// #71: one pid, watched live and streamed at the same time.
		{name: "pid with serve and tui", pid: 42, serveAddr: sock, withTUI: true},
		{name: "pid with no-ebpf", pid: 42, noEBPF: true},
		// #72: no target named + --serve is the on-demand mode; subscribers say
		// which pid they want.
		{name: "no target with serve", serveAddr: sock},
		{name: "no target with serve and max-targets", serveAddr: sock},
		{name: "no target at all", wantErrHas: "--pid is required"},
		// There is no one process for the TUI to draw when the target is
		// whatever each subscriber asks for.
		{name: "no target with serve and tui", serveAddr: sock, withTUI: true,
			wantErrHas: "--tui needs a target"},
		{name: "negative pid", pid: -5, wantErrHas: "not a valid PID"},

		{name: "cgroup with serve", cgroup: "/kubepods.slice/x.scope", serveAddr: sock},
		{name: "cgroup by container id", cgroup: "abc123def456", serveAddr: sock},

		// A cgroup subtree is a set of processes: the TUI has one header, one
		// thread table and one fd list, so there is nowhere to put it.
		{name: "cgroup without serve", cgroup: "/x.scope", wantErrHas: "requires --serve"},
		// The subtree filter runs in the kernel.
		{name: "cgroup with no-ebpf", cgroup: "/x.scope", serveAddr: sock, noEBPF: true,
			wantErrHas: "needs eBPF"},
		// Two different targets.
		{name: "cgroup and pid together", pid: 42, cgroup: "/x.scope", serveAddr: sock,
			wantErrHas: "pass one"},
		// --tui does not make a subtree renderable either.
		{name: "cgroup with tui", cgroup: "/x.scope", serveAddr: sock, withTUI: true,
			wantErrHas: "cannot be shown in the TUI"},

		// --for (#156): a report has room for a subtree, so a cgroup needs no
		// --serve there. It still needs the kernel filter, and a target.
		{name: "for with pid", pid: 42, capture: true},
		{name: "for with pid and no-ebpf", pid: 42, noEBPF: true, capture: true},
		{name: "for with cgroup", cgroup: "/x.scope", capture: true},
		{name: "for with cgroup and no-ebpf", cgroup: "/x.scope", noEBPF: true, capture: true,
			wantErrHas: "needs eBPF"},
		{name: "for with no target", capture: true, wantErrHas: "--for needs a target"},
		{name: "for with cgroup and pid", pid: 42, cgroup: "/x.scope", capture: true,
			wantErrHas: "pass one"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkTargetFlags(tc.pid, tc.cgroup, tc.serveAddr, tc.noEBPF, tc.withTUI, tc.capture, false)
			if tc.wantErrHas == "" {
				if err != nil {
					t.Fatalf("checkTargetFlags = %v, want accepted", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("checkTargetFlags = nil, want error containing %q", tc.wantErrHas)
			}
			if !strings.Contains(err.Error(), tc.wantErrHas) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErrHas)
			}
		})
	}
}

// The headline property of #119: with no flag, nothing off-image is consulted —
// not the network, and not a cache directory either. DEBUGINFOD_URLS being set
// in the environment does not by itself send a profiler to the internet.
func TestSymbolOptionsOffByDefault(t *testing.T) {
	t.Setenv("DEBUGINFOD_URLS", "https://debuginfod.example")
	got, err := symbolOptions(false, "", "")
	if err != nil {
		t.Fatalf("symbolOptions: %v", err)
	}
	if got.Enabled() {
		t.Errorf("no flags gave %+v, want nothing configured", got)
	}
}

func TestSymbolOptions(t *testing.T) {
	cacheDir := t.TempDir()

	t.Run("debuginfod reads the environment", func(t *testing.T) {
		t.Setenv("DEBUGINFOD_URLS", "https://a.example https://b.example")
		got, err := symbolOptions(true, "", cacheDir)
		if err != nil {
			t.Fatalf("symbolOptions: %v", err)
		}
		if len(got.URLs) != 2 || got.URLs[0] != "https://a.example" {
			t.Errorf("URLs = %v", got.URLs)
		}
		if got.CacheDir != cacheDir {
			t.Errorf("CacheDir = %q, want %q", got.CacheDir, cacheDir)
		}
	})

	t.Run("explicit urls override the environment", func(t *testing.T) {
		t.Setenv("DEBUGINFOD_URLS", "https://env.example")
		got, err := symbolOptions(false, "https://flag.example", cacheDir)
		if err != nil {
			t.Fatalf("symbolOptions: %v", err)
		}
		if len(got.URLs) != 1 || got.URLs[0] != "https://flag.example" {
			t.Errorf("URLs = %v, want the flag's server", got.URLs)
		}
	})

	// --symbol-cache alone is the offline shape: a vendor bundle on disk, and
	// no server to reach.
	t.Run("cache alone stays offline", func(t *testing.T) {
		t.Setenv("DEBUGINFOD_URLS", "https://env.example")
		got, err := symbolOptions(false, "", cacheDir)
		if err != nil {
			t.Fatalf("symbolOptions: %v", err)
		}
		if len(got.URLs) != 0 {
			t.Errorf("URLs = %v, want none", got.URLs)
		}
		if !got.Enabled() || got.CacheDir != cacheDir {
			t.Errorf("got %+v, want the store enabled", got)
		}
	})

	t.Run("a store is defaulted once a server is in play", func(t *testing.T) {
		got, err := symbolOptions(false, "https://a.example", "")
		if err != nil {
			t.Fatalf("symbolOptions: %v", err)
		}
		if got.CacheDir == "" {
			t.Error("CacheDir empty: a fetch would repeat every run")
		}
	})

	// Rejected at startup, not as a per-module warning during a capture.
	t.Run("bad input fails early", func(t *testing.T) {
		t.Setenv("DEBUGINFOD_URLS", "")
		if _, err := symbolOptions(true, "", ""); err == nil {
			t.Error("--debuginfod with no servers: want an error")
		}
		if _, err := symbolOptions(false, "not-a-url", ""); err == nil {
			t.Error("--debuginfod-urls with a bad URL: want an error")
		}
		if _, err := symbolOptions(false, "   ", ""); err == nil {
			t.Error("--debuginfod-urls naming nothing: want an error")
		}
	})
}

func TestCheckCaptureFlags(t *testing.T) {
	const sock = "unix:///run/ptop.sock"
	type flags struct {
		forDur              time.Duration
		top                 int
		probes, disable     string
		serveAddr           string
		withTUI, tlsCapture bool
		given               []string
	}
	cases := []struct {
		name       string
		f          flags
		wantErrHas string // "" = must be accepted
	}{
		{name: "no --for at all", f: flags{top: 10}},
		{name: "a window", f: flags{forDur: 10 * time.Second, top: 10}},
		{name: "the shortest window", f: flags{forDur: time.Second, top: 1}},
		{name: "the longest window", f: flags{forDur: 5 * time.Minute, top: 50}},
		{name: "with --probes", f: flags{forDur: 10 * time.Second, top: 10, probes: "cpu,heap"}},
		{name: "with --disable", f: flags{forDur: 10 * time.Second, top: 10, disable: "io"}},

		{name: "under a second", f: flags{forDur: 500 * time.Millisecond, top: 10}, wantErrHas: "from 1s to 5m0s"},
		// No override: an agent that forgot a unit has not asked for an hour.
		{name: "over five minutes", f: flags{forDur: 6 * time.Minute, top: 10}, wantErrHas: "from 1s to 5m0s"},
		{name: "a negative window", f: flags{forDur: -time.Second, top: 10}, wantErrHas: "from 1s to 5m0s"},
		{name: "top of zero", f: flags{forDur: time.Second, top: 0}, wantErrHas: "from 1 to 50"},
		{name: "top over the bound", f: flags{forDur: time.Second, top: 51}, wantErrHas: "from 1 to 50"},
		{name: "with --serve", f: flags{forDur: time.Second, top: 10, serveAddr: sock}, wantErrHas: "cannot also --serve"},
		{name: "with --tui", f: flags{forDur: time.Second, top: 10, withTUI: true}, wantErrHas: "not the TUI"},
		{name: "with --tls", f: flags{forDur: time.Second, top: 10, tlsCapture: true}, wantErrHas: "refuses --tls"},
		{name: "--probes and --disable", f: flags{forDur: time.Second, top: 10, probes: "cpu", disable: "io"},
			wantErrHas: "pass one"},
		// Flags that only shape a report are a mistake without one.
		{name: "--top without --for", f: flags{top: 20, given: []string{"top"}}, wantErrHas: "--top goes with --for"},
		{name: "--probes without --for", f: flags{top: 10, probes: "cpu", given: []string{"probes"}},
			wantErrHas: "--probes goes with --for"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			given := map[string]bool{}
			for _, g := range tc.f.given {
				given[g] = true
			}
			err := checkCaptureFlags(tc.f.forDur, tc.f.top, tc.f.probes, tc.f.disable, tc.f.serveAddr,
				tc.f.withTUI, tc.f.tlsCapture, given)
			if tc.wantErrHas == "" {
				if err != nil {
					t.Fatalf("checkCaptureFlags = %v, want accepted", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErrHas) {
				t.Fatalf("checkCaptureFlags = %v, want an error containing %q", err, tc.wantErrHas)
			}
		})
	}
}

func TestCaptureExitCode(t *testing.T) {
	active := &pb.ProbeInfo{Name: "cpu", State: pb.ProbeState_PROBE_STATE_ACTIVE}
	failed := &pb.ProbeInfo{Name: "heap", State: pb.ProbeState_PROBE_STATE_FAILED}
	rep := func(end pb.WindowEnd, probes ...*pb.ProbeInfo) *pb.CaptureReport {
		return &pb.CaptureReport{
			Target: &pb.TargetInfo{Probes: probes},
			Window: &pb.CaptureWindow{End: end},
		}
	}
	cases := []struct {
		name string
		r    *pb.CaptureReport
		want int
	}{
		{"complete", rep(pb.WindowEnd_WINDOW_END_COMPLETE, active), 0},
		// A partial probe set is still a measurement.
		{"complete with a failed probe", rep(pb.WindowEnd_WINDOW_END_COMPLETE, active, failed), 0},
		{"target exited", rep(pb.WindowEnd_WINDOW_END_TARGET_EXITED, active), 3},
		{"interrupted", rep(pb.WindowEnd_WINDOW_END_INTERRUPTED, active), 130},
		// Nothing attached outranks how the window ended: there is nothing to read.
		{"nothing attached", rep(pb.WindowEnd_WINDOW_END_COMPLETE, failed), 4},
		{"nothing attached, target exited", rep(pb.WindowEnd_WINDOW_END_TARGET_EXITED, failed), 4},
		{"no probe set", rep(pb.WindowEnd_WINDOW_END_COMPLETE), 4},
	}
	for _, tc := range cases {
		if got := captureExitCode(tc.r); got != tc.want {
			t.Errorf("%s: captureExitCode = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestCheckMCPFlags(t *testing.T) {
	cases := []struct {
		mcp   bool
		given []string
		want  string // "" accepted
	}{
		{false, nil, ""},
		{true, []string{"mcp-allow-uid", "no-ebpf", "disable", "overhead-budget", "cpu-sample-hz"}, ""},
		{false, []string{"mcp-allow-any"}, "--mcp-allow-any goes with --mcp"},
		{false, []string{"mcp-allow-cgroup"}, "goes with --mcp"},
		{true, []string{"mcp-allow-any", "pid"}, "--pid does not go with --mcp"},
		{true, []string{"mcp-allow-any", "for"}, "--for does not go"},
		{true, []string{"mcp-allow-any", "serve"}, "--serve does not go"},
		{true, []string{"mcp-allow-any", "tls-bytes"}, "--tls-bytes does not go"},
		{true, []string{"mcp-allow-any", "probes"}, "--probes does not go"},
	}
	for _, c := range cases {
		given := map[string]bool{}
		for _, f := range c.given {
			given[f] = true
		}
		err := checkMCPFlags(c.mcp, given)
		if (c.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.want)) {
			t.Errorf("mcp=%v %v: %v, want %q", c.mcp, c.given, err, c.want)
		}
	}
}

// runMainEnv makes the test binary run ptop's main instead of the tests, so a
// test can drive the real binary's stdio.
const runMainEnv = "PTOP_TEST_RUN_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func ptopCmd(args ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), runMainEnv+"=1")
	return cmd
}

// --mcp refuses to start without a scope: the agent could otherwise name any
// process on the host.
func TestMCPNeedsAScope(t *testing.T) {
	var stderr strings.Builder
	cmd := ptopCmd("--mcp", "--no-ebpf")
	cmd.Stderr = &stderr
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 2 {
		t.Fatalf("exit = %v, want 2", err)
	}
	if !strings.Contains(stderr.String(), "--mcp-allow-any") {
		t.Errorf("stderr does not name the scope flags: %s", stderr.String())
	}
}

// The real binary in --mcp mode: stdout carries JSON-RPC frames and nothing
// else, from the first byte, while ptop's own messages go to stderr. A capture
// of this test process comes back as a report.
func TestMCPStdoutCarriesOnlyTheProtocol(t *testing.T) {
	cmd := ptopCmd("--mcp", "--mcp-allow-uid", fmt.Sprint(os.Getuid()), "--no-ebpf")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	send := func(frame string) {
		if _, err := io.WriteString(stdin, frame+"\n"); err != nil {
			t.Fatalf("write %s: %v", frame, err)
		}
	}
	lines := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	type frame struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      *int            `json:"id"`
		Method  string          `json:"method"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	// await reads frames until the response with id, failing on anything that
	// is not JSON-RPC.
	await := func(id int) frame {
		t.Helper()
		timeout := time.After(30 * time.Second)
		for {
			select {
			case l, ok := <-lines:
				if !ok {
					t.Fatalf("stdout closed before response %d; stderr:\n%s", id, stderr.String())
				}
				var f frame
				if err := json.Unmarshal([]byte(l), &f); err != nil || f.JSONRPC != "2.0" {
					t.Fatalf("stdout carried a line that is not JSON-RPC: %q", l)
				}
				if f.ID != nil && *f.ID == id {
					if len(f.Error) > 0 {
						t.Fatalf("response %d is an error: %s", id, f.Error)
					}
					return f
				}
			case <-timeout:
				t.Fatalf("no response %d; stderr:\n%s", id, stderr.String())
			}
		}
	}

	send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`)
	init := await(1)
	if !strings.Contains(string(init.Result), `"name":"ptop"`) {
		t.Errorf("initialize = %s, want serverInfo ptop", init.Result)
	}
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if l := await(2); !strings.Contains(string(l.Result), `"capture"`) || !strings.Contains(string(l.Result), `"caps"`) {
		t.Errorf("tools/list = %s", l.Result)
	}
	send(fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"capture","arguments":{"pid":%d,"seconds":1,"probes":["cpu"]}}}`, os.Getpid()))
	call := await(3)
	var res struct {
		IsError           bool `json:"isError"`
		StructuredContent struct {
			Window struct{ End string } `json:"window"`
		} `json:"structuredContent"`
	}
	if err := json.Unmarshal(call.Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.IsError || res.StructuredContent.Window.End != "WINDOW_END_COMPLETE" {
		t.Errorf("capture = %s", call.Result)
	}

	// Closing stdin ends the session, and ptop with it.
	stdin.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("ptop --mcp exited with %v after stdin closed", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ptop --mcp did not exit after stdin closed")
	}
	for l := range lines {
		t.Errorf("stdout carried %q after the session", l)
	}
	if !strings.Contains(stderr.String(), "[ptop] MCP on stdio") {
		t.Errorf("stderr is missing the startup line: %s", stderr.String())
	}
}
