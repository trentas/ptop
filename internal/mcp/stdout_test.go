//go:build linux || darwin

package mcp

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const takeStdoutChild = "PTOP_TEST_TAKE_STDOUT_CHILD"

// After TakeStdout, the protocol's file is the only way to the real stdout: a
// stray write, through os.Stdout or straight to fd 1, lands on stderr. Run in a
// child, since it rewires the process's descriptors.
func TestTakeStdout(t *testing.T) {
	if os.Getenv(takeStdoutChild) == "1" {
		proto, err := TakeStdout()
		if err != nil {
			fmt.Fprintln(os.Stderr, "TakeStdout:", err)
			os.Exit(1)
		}
		fmt.Println("stray via fmt")
		os.NewFile(1, "fd1").WriteString("stray via fd 1\n")
		proto.WriteString(`{"jsonrpc":"2.0"}` + "\n")
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestTakeStdout$")
	cmd.Env = append(os.Environ(), takeStdoutChild+"=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("child: %v\nstderr: %s", err, stderr.String())
	}
	if got := stdout.String(); got != `{"jsonrpc":"2.0"}`+"\n" {
		t.Errorf("stdout = %q, want the protocol frame and nothing else", got)
	}
	for _, want := range []string{"stray via fmt", "stray via fd 1"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr is missing %q: %q", want, stderr.String())
		}
	}
}
