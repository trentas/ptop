package main

import (
	"runtime/debug"
	"testing"

	"github.com/trentas/ptop/internal/serve"
)

func vcs(rev, at, modified string) *debug.BuildInfo {
	return &debug.BuildInfo{
		Main: debug.Module{Version: "(devel)"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: rev},
			{Key: "vcs.time", Value: at},
			{Key: "vcs.modified", Value: modified},
		},
	}
}

func TestResolveBuild(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		version, commit, date string
		bi                    *debug.BuildInfo
		want                  serve.PtopBuild
	}{
		{
			name:    "release: the -ldflags values win over the embedded VCS info",
			version: "v1.9.0", commit: "abc123", date: "2026-10-20T10:00:00Z",
			bi:   vcs("ffff", "2026-01-01T00:00:00Z", "true"),
			want: serve.PtopBuild{Version: "v1.9.0", Commit: "abc123", BuildDate: "2026-10-20T10:00:00Z"},
		},
		{
			name:    "dev build from a clean checkout names its commit",
			version: "dev", commit: "none", date: "unknown",
			bi:   vcs("f8d8ad3", "2026-10-15T02:57:27Z", "false"),
			want: serve.PtopBuild{Version: "dev", Commit: "f8d8ad3", BuildDate: "2026-10-15T02:57:27Z"},
		},
		{
			name:    "dev build from a modified tree says so",
			version: "dev", commit: "none", date: "unknown",
			bi:   vcs("f8d8ad3", "2026-10-15T02:57:27Z", "true"),
			want: serve.PtopBuild{Version: "dev", Commit: "f8d8ad3+dirty", BuildDate: "2026-10-15T02:57:27Z"},
		},
		{
			name:    "go install @version names the module version",
			version: "dev", commit: "none", date: "unknown",
			bi:   &debug.BuildInfo{Main: debug.Module{Version: "v1.9.0"}},
			want: serve.PtopBuild{Version: "v1.9.0"},
		},
		{
			name:    "nothing known: dev, and the rest empty — never none/unknown on the wire",
			version: "dev", commit: "none", date: "unknown",
			want: serve.PtopBuild{Version: "dev"},
		},
	} {
		if got := resolveBuild(tc.version, tc.commit, tc.date, tc.bi); got != tc.want {
			t.Errorf("%s:\n got  %+v\n want %+v", tc.name, got, tc.want)
		}
	}
}

func TestVersionLineSpellsOutUnknown(t *testing.T) {
	if got, want := versionLine(serve.PtopBuild{Version: "dev"}), "ptop dev (commit unknown, built unknown)"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
