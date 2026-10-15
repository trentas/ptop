package main

import (
	"runtime/debug"

	"github.com/trentas/ptop/internal/serve"
)

// Variables injected via -ldflags in the release build (goreleaser).
// In dev (`go build`/`go run`), they stay as "dev"/"none"/"unknown".
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

// buildIdentity is this binary's identity as the handshake and --version state
// it (#145). A release carries the -ldflags values. A dev build fills what it
// can from the VCS information Go embeds when it builds from a checkout, so
// even a local build names its commit — and "+dirty" when that commit is not
// the whole story. Anything still unknown is "".
func buildIdentity() serve.PtopBuild {
	bi, _ := debug.ReadBuildInfo()
	return resolveBuild(version, commit, buildDate, bi)
}

// resolveBuild is buildIdentity with its inputs passed in, for tests.
func resolveBuild(version, commit, date string, bi *debug.BuildInfo) serve.PtopBuild {
	b := serve.PtopBuild{Version: tagForm(version)}
	if commit != "none" {
		b.Commit = commit
	}
	if date != "unknown" {
		b.BuildDate = date
	}
	if bi == nil {
		return b
	}
	// `go install github.com/trentas/ptop/cmd/ptop@v1.9.0` names the module
	// version even without -ldflags.
	if b.Version == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		b.Version = bi.Main.Version
	}
	var rev, at string
	dirty := false
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.time":
			at = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if b.Commit == "" && rev != "" {
		b.Commit = rev
		if dirty {
			b.Commit += "+dirty"
		}
	}
	if b.BuildDate == "" {
		b.BuildDate = at
	}
	return b
}

// versionLine renders the identity for --version, spelling out what is unknown.
func versionLine(b serve.PtopBuild) string {
	or := func(s, unknown string) string {
		if s == "" {
			return unknown
		}
		return s
	}
	return "ptop " + or(b.Version, "dev") + " (commit " + or(b.Commit, "unknown") + ", built " + or(b.BuildDate, "unknown") + ")"
}

// tagForm spells a release version the way its tag and Go's module version do:
// "v1.9.0". goreleaser injects {{ .Version }}, which is the tag WITHOUT the v,
// so a release would otherwise say "1.9.0" while every build from a checkout
// says "v1.9.1-0.…" — two spellings of one scheme for a consumer to reconcile.
func tagForm(v string) string {
	if v != "" && v[0] >= '0' && v[0] <= '9' {
		return "v" + v
	}
	return v
}
