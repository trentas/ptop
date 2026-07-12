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
