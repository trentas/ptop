package tui

import (
	"os"
	"strings"
	"testing"
)

// TestDetectRuntime_self runs the detector against the test binary itself,
// which is a Go program — so it must report a "Go <major>.<minor>" badge.
// This exercises the full path: osExePath (per-OS) → buildinfo.ReadFile.
func TestDetectRuntime_self(t *testing.T) {
	got := detectRuntime(os.Getpid())
	if !strings.HasPrefix(got, "Go ") {
		t.Fatalf("detectRuntime(self) = %q, want a \"Go x.y\" badge (test binary is Go)", got)
	}
	t.Logf("self runtime = %q", got)
}

func TestDetectRuntime_invalidPID(t *testing.T) {
	if got := detectRuntime(0); got != "" {
		t.Fatalf("detectRuntime(0) = %q, want empty", got)
	}
	if got := detectRuntime(-1); got != "" {
		t.Fatalf("detectRuntime(-1) = %q, want empty", got)
	}
}

func TestFormatGoVersion(t *testing.T) {
	cases := map[string]string{
		"go1.22.3": "Go 1.22",
		"go1.22":   "Go 1.22",
		"go1.21.0": "Go 1.21",
		"1.20.5":   "Go 1.20", // tolerate a missing "go" prefix
		"go2":      "Go 2",    // no minor → pass through
	}
	for in, want := range cases {
		if got := formatGoVersion(in); got != want {
			t.Errorf("formatGoVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRuntimeFromBasename(t *testing.T) {
	cases := map[string]string{
		"python3.11":        "Python",
		"python":            "Python",
		"node":              "Node.js",
		"nodejs":            "Node.js",
		"deno":              "Deno",
		"bun":               "Bun",
		"java":              "JVM",
		"ruby":              "Ruby",
		"perl":              "Perl",
		"PYTHON3":           "Python", // case-insensitive
		"some-daemon":       "",       // unknown → no badge
		"identityservicesd": "",
	}
	for in, want := range cases {
		if got := runtimeFromBasename(in); got != want {
			t.Errorf("runtimeFromBasename(%q) = %q, want %q", in, got, want)
		}
	}
}
