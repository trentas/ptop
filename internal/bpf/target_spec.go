package bpf

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// Target modes, mirroring PTOP_TARGET_* in programs/target.bpf.h.
const (
	targetModePID    uint32 = 0
	targetModeCgroup uint32 = 1
)

// Target names what the eBPF programs should filter on: a single process, or
// every process in a cgroup subtree.
//
// PID mode is resolved inside the target's own PID namespace, so a
// namespace-local pid (what /proc and ps show) matches even from a nested
// namespace. Cgroup mode needs no pid at all, which is what lets ptop attach
// to a container or a whole pod whose processes are not known in advance
// (#94), and it follows forks into the subtree for free.
type Target struct {
	PID int

	// Cgroup is a cgroup path or a container id; non-empty selects cgroup mode.
	Cgroup string
}

// TargetPID targets one process by (namespace-local) pid.
func TargetPID(pid int) Target { return Target{PID: pid} }

// TargetCgroup targets every process in a cgroup subtree. spec is a path —
// absolute, or relative to the cgroup root as it appears in
// /proc/<pid>/cgroup — or a container id to look up in the tree.
func TargetCgroup(spec string) Target { return Target{Cgroup: spec} }

// IsCgroup reports whether t selects a cgroup subtree rather than a pid.
func (t Target) IsCgroup() bool { return t.Cgroup != "" }

func (t Target) String() string {
	if t.IsCgroup() {
		return "cgroup " + t.Cgroup
	}
	return fmt.Sprintf("pid %d", t.PID)
}

// validate rejects a Target that names nothing to trace.
func (t Target) validate() error {
	if t.IsCgroup() {
		return nil
	}
	if t.PID <= 0 {
		return fmt.Errorf("invalid pid %d", t.PID)
	}
	return nil
}

// cgroup2Root returns the mount point of the unified (v2) hierarchy, given the
// contents of /proc/self/mountinfo.
//
// v2 is required: the cgroup id the BPF helpers report is the one from the
// default hierarchy, so on a cgroup v1-only host there is nothing meaningful
// to target. On a hybrid host the first cgroup2 mount is the unified one
// (customarily /sys/fs/cgroup/unified).
func cgroup2Root(mountinfo string) (string, error) {
	for _, line := range strings.Split(mountinfo, "\n") {
		// mountinfo separates the variable-length optional fields from the
		// fstype with a literal " - ".
		sep := strings.Index(line, " - ")
		if sep < 0 {
			continue
		}
		fields := strings.Fields(line[:sep])
		rest := strings.Fields(line[sep+3:])
		if len(fields) < 5 || len(rest) < 1 || rest[0] != "cgroup2" {
			continue
		}
		return unescapeMountPath(fields[4]), nil
	}
	return "", errors.New("no cgroup2 (unified) hierarchy is mounted — cgroup targeting needs cgroup v2")
}

// unescapeMountPath undoes the octal escaping the kernel applies to the
// characters that would otherwise break mountinfo's field separation.
func unescapeMountPath(p string) string {
	for from, to := range map[string]string{`\040`: " ", `\011`: "\t", `\012`: "\n", `\134`: `\`} {
		p = strings.ReplaceAll(p, from, to)
	}
	return p
}

// cgroupLevel returns the depth of target below root, which is what
// bpf_get_current_ancestor_cgroup_id() needs to identify a subtree. The root
// itself is level 0.
func cgroupLevel(root, target string) (uint32, error) {
	r, t := path.Clean(root), path.Clean(target)
	if t == r {
		return 0, nil
	}
	if !strings.HasPrefix(t, r+"/") {
		return 0, fmt.Errorf("cgroup %q is not under the cgroup root %q", target, root)
	}
	rel := strings.Trim(strings.TrimPrefix(t, r), "/")
	return uint32(len(strings.Split(rel, "/"))), nil
}

// cgroupSearchDepth bounds the container-id walk. Even a deeply nested
// kubepods hierarchy (kubepods.slice → QoS slice → pod slice → container)
// stays well inside this, while a cgroup tree with thousands of leaves does
// not turn a typo into a full-filesystem scan.
const cgroupSearchDepth = 8

// cgroupPath maps a --cgroup spec to an absolute cgroup path. fsys must be
// rooted at root (os.DirFS(root)); it is only consulted for a container-id
// lookup.
func cgroupPath(fsys fs.FS, root, spec string) (string, error) {
	if spec == "" {
		return "", errors.New("empty cgroup spec")
	}
	if strings.HasPrefix(spec, "/") {
		// Either already absolute on the host, or the root-relative form that
		// /proc/<pid>/cgroup prints.
		if p := path.Clean(spec); p == path.Clean(root) || strings.HasPrefix(p, path.Clean(root)+"/") {
			return p, nil
		}
		return path.Join(root, spec), nil
	}
	rel, err := findCgroup(fsys, spec)
	if err != nil {
		return "", err
	}
	return path.Join(root, rel), nil
}

// findCgroup walks fsys — rooted at the cgroup mount — for a directory whose
// name contains needle, typically a container id. It returns the match
// relative to fsys.
//
// Ambiguity is an error: two containers whose ids share a prefix are a normal
// thing to hit with a short id, and picking one of them would attach the
// tracers to the wrong workload silently.
func findCgroup(fsys fs.FS, needle string) (string, error) {
	var hits []string
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// A corner of /sys/fs/cgroup this process cannot enter is not
			// fatal — the target may well be elsewhere in the tree.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if p == "." || !d.IsDir() {
			return nil
		}
		if strings.Count(p, "/")+1 > cgroupSearchDepth {
			return fs.SkipDir
		}
		if strings.Contains(path.Base(p), needle) {
			// Whatever is below a match belongs to the match.
			hits = append(hits, p)
			return fs.SkipDir
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("search cgroup tree for %q: %w", needle, err)
	}

	switch len(hits) {
	case 0:
		return "", fmt.Errorf("no cgroup matches %q", needle)
	case 1:
		return hits[0], nil
	default:
		sort.Strings(hits)
		shown := hits
		if len(shown) > 3 {
			shown = shown[:3]
		}
		return "", fmt.Errorf("%q matches %d cgroups (%s...) — pass a full path or a longer id",
			needle, len(hits), strings.Join(shown, ", "))
	}
}
