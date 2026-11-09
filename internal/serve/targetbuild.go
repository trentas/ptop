package serve

import (
	"debug/buildinfo"
	"runtime/debug"
	"strings"

	pb "github.com/trentas/ptop/pkg/streampb"
)

// readTargetBuild is the target binary's build for the handshake (#157): nil in
// cgroup mode, where one process's build is not the subtree's, and whenever the
// executable records no Go build info or cannot be read. A consumer reads nil
// as unknown, which is what it is.
func readTargetBuild(t Target) *pb.TargetBuild {
	if t.IsCgroup() || t.PID <= 0 {
		return nil
	}
	exe := targetExe(t.PID)
	if exe == "" {
		return nil
	}
	bi, err := buildinfo.ReadFile(exe)
	if err != nil {
		return nil
	}
	return targetBuildFrom(bi)
}

// targetBuildFrom renders a binary's build info for the wire. Of the build
// settings it keeps the vcs.* keys only: -ldflags lands among the others, and
// `-X main.apiKey=...` is a known way to put a secret into a binary. Module
// paths and versions describe the software, not the customer's data.
func targetBuildFrom(bi *debug.BuildInfo) *pb.TargetBuild {
	tb := &pb.TargetBuild{
		GoVersion: bi.GoVersion,
		Path:      bi.Path,
		Main:      goModule(&bi.Main),
	}
	for _, d := range bi.Deps {
		if m := goModule(d); m != nil {
			tb.Deps = append(tb.Deps, m)
		}
	}
	for _, s := range bi.Settings {
		if s.Key == "vcs" || strings.HasPrefix(s.Key, "vcs.") {
			tb.Vcs = append(tb.Vcs, &pb.BuildSetting{Key: s.Key, Value: s.Value})
		}
	}
	return tb
}

// goModule renders one module, nil when the binary records none (a main
// package built outside any module has an empty Main).
func goModule(m *debug.Module) *pb.GoModule {
	if m == nil || m.Path == "" {
		return nil
	}
	return &pb.GoModule{Path: m.Path, Version: m.Version, Sum: m.Sum, Replace: goModule(m.Replace)}
}
