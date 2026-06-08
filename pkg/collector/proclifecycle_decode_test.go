package collector

import (
	"testing"
	"time"
)

func TestProcKindName(t *testing.T) {
	cases := map[uint32]string{
		0: "fork", 1: "exec", 2: "exit", 7: "kind7",
	}
	for k, want := range cases {
		if got := procKindName(k); got != want {
			t.Errorf("procKindName(%d) = %q, want %q", k, got, want)
		}
	}
}

func TestDecodeProcLifecycle(t *testing.T) {
	ts := time.Now()
	comm := append([]byte("bash"), 0, 'x') // NUL-terminated, trailing garbage
	fname := append([]byte("/usr/bin/ls"), 0)

	fork := decodeProcLifecycle(ts, procKindFork, 4242, 7, comm, fname)
	if fork.Kind != "fork" || fork.PID != 4242 || fork.PPID != 7 {
		t.Errorf("fork = %+v", fork)
	}
	if fork.Comm != "bash" {
		t.Errorf("fork.Comm = %q, want bash", fork.Comm)
	}
	// Filename must NOT leak into a fork event even if a buffer is passed.
	if fork.Filename != "" {
		t.Errorf("fork.Filename = %q, want empty", fork.Filename)
	}

	exec := decodeProcLifecycle(ts, procKindExec, 4242, 0, comm, fname)
	if exec.Kind != "exec" || exec.Filename != "/usr/bin/ls" {
		t.Errorf("exec = %+v", exec)
	}

	exit := decodeProcLifecycle(ts, procKindExit, 4242, 0, comm, nil)
	if exit.Kind != "exit" || exit.Filename != "" {
		t.Errorf("exit = %+v", exit)
	}
	if !exit.Timestamp.Equal(ts) {
		t.Errorf("timestamp not preserved")
	}
}
