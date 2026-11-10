package serve

import (
	"runtime/debug"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/prototext"
)

// -ldflags lands in the build settings, and `-X main.apiKey=...` is a known
// way to put a secret into a binary. Only the vcs.* settings travel.
func TestTargetBuildKeepsOnlyTheVCSSettings(t *testing.T) {
	const secret = "sk_live_do_not_ship"
	bi := &debug.BuildInfo{
		GoVersion: "go1.26.10",
		Path:      "github.com/acme/svc/cmd/api",
		Main:      debug.Module{Path: "github.com/acme/svc", Version: "(devel)"},
		Settings: []debug.BuildSetting{
			{Key: "-ldflags", Value: "-s -w -X main.apiKey=" + secret},
			{Key: "-tags", Value: "netgo"},
			{Key: "CGO_ENABLED", Value: "0"},
			{Key: "GOARCH", Value: "amd64"},
			{Key: "vcs", Value: "git"},
			{Key: "vcs.revision", Value: "0123abcd"},
			{Key: "vcs.time", Value: "2026-11-01T10:00:00Z"},
			{Key: "vcs.modified", Value: "false"},
		},
	}
	tb := targetBuildFrom(bi)
	var keys []string
	for _, s := range tb.GetVcs() {
		keys = append(keys, s.GetKey())
	}
	if got := strings.Join(keys, ","); got != "vcs,vcs.revision,vcs.time,vcs.modified" {
		t.Errorf("settings carried = %s, want the four vcs ones", got)
	}
	if txt := prototext.Format(tb); strings.Contains(txt, secret) || strings.Contains(txt, "ldflags") {
		t.Errorf("the ldflags reached the wire:\n%s", txt)
	}
}

func TestTargetBuildModules(t *testing.T) {
	bi := &debug.BuildInfo{
		GoVersion: "go1.26.10",
		Path:      "github.com/acme/svc/cmd/api",
		Main:      debug.Module{Path: "github.com/acme/svc", Version: "v1.4.0", Sum: "h1:main="},
		Deps: []*debug.Module{
			{Path: "github.com/jackc/pgx/v5", Version: "v5.7.1", Sum: "h1:pgx="},
			{Path: "github.com/acme/fork", Version: "v1.0.0", Replace: &debug.Module{Path: "../fork"}},
			nil,
		},
	}
	tb := targetBuildFrom(bi)
	if tb.GetGoVersion() != "go1.26.10" || tb.GetPath() != "github.com/acme/svc/cmd/api" {
		t.Errorf("go/path = %q/%q", tb.GetGoVersion(), tb.GetPath())
	}
	if m := tb.GetMain(); m.GetPath() != "github.com/acme/svc" || m.GetVersion() != "v1.4.0" || m.GetSum() != "h1:main=" {
		t.Errorf("main = %v", m)
	}
	deps := tb.GetDeps()
	if len(deps) != 2 {
		t.Fatalf("deps = %d, want 2 (a nil entry is skipped)", len(deps))
	}
	if d := deps[0]; d.GetPath() != "github.com/jackc/pgx/v5" || d.GetVersion() != "v5.7.1" || d.GetReplace() != nil {
		t.Errorf("deps[0] = %v", d)
	}
	if r := deps[1].GetReplace(); r.GetPath() != "../fork" || r.GetVersion() != "" {
		t.Errorf("a local replace = %v, want ../fork with no version", r)
	}
}

// A main package built outside any module records an empty Main: no module,
// rather than a module with no path.
func TestTargetBuildWithoutAModule(t *testing.T) {
	if m := targetBuildFrom(&debug.BuildInfo{GoVersion: "go1.26.10", Path: "command-line-arguments"}).GetMain(); m != nil {
		t.Errorf("main = %v, want absent", m)
	}
}
