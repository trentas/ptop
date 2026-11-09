//go:build linux

package serve

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"testing"
)

// The test binary is a Go binary built from this module, and the runtime's
// own view of its build is the planted answer. (A test binary records its main
// module and no dependencies; the rendering of a dependency list is
// TestTargetBuildModules.)
func TestHandshakeCarriesTheTargetsBuild(t *testing.T) {
	want, ok := debug.ReadBuildInfo()
	if !ok {
		t.Skip("this test binary carries no build info")
	}
	ti := handshakeFor(t, TargetPID(os.Getpid()))
	tb := ti.GetTargetBuild()
	if tb == nil {
		t.Fatal("no target_build in the handshake of a Go target")
	}
	if tb.GetGoVersion() != runtime.Version() {
		t.Errorf("go version = %q, want %q", tb.GetGoVersion(), runtime.Version())
	}
	if tb.GetMain().GetPath() != "github.com/trentas/ptop" || tb.GetMain().GetPath() != want.Main.Path {
		t.Errorf("main module = %q, want github.com/trentas/ptop", tb.GetMain().GetPath())
	}
	if tb.GetPath() != want.Path || len(tb.GetDeps()) != len(want.Deps) {
		t.Errorf("path %q with %d deps, the runtime says %q with %d", tb.GetPath(), len(tb.GetDeps()), want.Path, len(want.Deps))
	}
}

func TestHandshakeOmitsTheBuildInCgroupMode(t *testing.T) {
	ti := handshakeFor(t, TargetCgroup("/sys/fs/cgroup/x.scope", 4026532))
	if tb := ti.GetTargetBuild(); tb != nil {
		t.Errorf("cgroup mode carried a build: %v", tb)
	}
}

// A target with no Go build info (here a C binary) has no target_build, so
// absent stays "unknown" and never becomes an empty build.
func TestNonGoTargetHasNoBuild(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep(1) on PATH")
	}
	cmd := exec.Command(sleep, "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if tb := readTargetBuild(TargetPID(cmd.Process.Pid)); tb != nil {
		t.Errorf("a C binary carried a Go build: %v", tb)
	}
}

// A subscriber that names its pid gets the same handshake as a fixed target.
func TestOnDemandHubCarriesTheTargetsBuild(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg := newOnDemandRegistry(ctx, newTestFactory().make, 4, PtopBuild{})
	hub, _, release, err := reg.acquire(os.Getpid())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer release()
	if got := hub.targetInfo().GetTargetBuild().GetMain().GetPath(); got != "github.com/trentas/ptop" {
		t.Errorf("on-demand handshake main module = %q, want github.com/trentas/ptop", got)
	}
}
