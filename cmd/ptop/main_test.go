package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/trentas/ptop/pkg/collector"
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
			err := checkTargetFlags(tc.pid, tc.cgroup, tc.serveAddr, tc.noEBPF, tc.withTUI, tc.capture)
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

func TestCaptureDisableLeavesHeapOffUnlessNamed(t *testing.T) {
	// Without --probes: everything but heap, and what --disable named.
	got, err := captureDisable("", map[string]bool{collector.SubsystemIO: true})
	if err != nil {
		t.Fatal(err)
	}
	if !got[collector.SubsystemHeap] || !got[collector.SubsystemIO] || len(got) != 2 {
		t.Errorf("captureDisable(\"\", io) = %v, want exactly heap and io off", got)
	}
	// With --probes: exactly what it names, heap included when named.
	got, err = captureDisable("cpu,heap", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got[collector.SubsystemHeap] || got[collector.SubsystemCPU] || !got[collector.SubsystemIO] {
		t.Errorf("captureDisable(cpu,heap) = %v, want cpu and heap on, io off", got)
	}
	if _, err := captureDisable("cpu,nonsense", nil); err == nil {
		t.Error("captureDisable(cpu,nonsense) accepted an unknown subsystem")
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
