package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
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
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkTargetFlags(tc.pid, tc.cgroup, tc.serveAddr, tc.noEBPF, tc.withTUI)
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
