package mcp

import (
	"errors"
	"fmt"
	"os/user"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/trentas/ptop/internal/bpf"
)

// Scope is which targets an agent may name (#187).
//
// `ptop --mcp` runs with the capabilities ptop needs, and those let it attach
// to any process on the host. The agent driving it names the target, and a
// report carries file paths and remote addresses as they are (#156). So the
// operator says, at launch, which processes the agent may look at, and ptop
// refuses to start until they have: the --serve-insecure pattern, where the
// dangerous shape exists but has to be asked for.
//
// The scope is checked when a capture is asked for. A target that changes its
// uid during the window (a setuid exec) is not checked again.
type Scope struct {
	// Any allows every process on the host (--mcp-allow-any).
	Any bool
	// UIDs allows a process every one of whose uids (real, effective, saved,
	// filesystem) is in the set (--mcp-allow-uid). All four, because a setuid
	// program started by an allowed user runs with someone else's privileges,
	// and holds their secrets.
	UIDs []uint32
	// Cgroups allows a process in one of these cgroup subtrees, and a cgroup
	// target inside one (--mcp-allow-cgroup). Absolute paths, as
	// bpf.ResolveCgroupSpec returns them.
	Cgroups []string

	// Lookups, replaced in tests.
	uidsOf   func(pid int) ([]uint32, error)
	cgroupOf func(pid int) (string, error)
}

// ParseScope builds the scope from the --mcp-allow-* flags. uids is a
// comma-separated list of uids or user names, cgroups one of cgroup paths or
// container ids, each resolved now: a typo fails at launch, and the log says
// what an id matched.
func ParseScope(allowAny bool, uids, cgroups string) (Scope, error) {
	s := Scope{Any: allowAny}
	if allowAny && (uids != "" || cgroups != "") {
		return Scope{}, errors.New("--mcp-allow-any already allows every process; drop --mcp-allow-uid and --mcp-allow-cgroup, or it")
	}
	for _, f := range splitList(uids) {
		uid, err := parseUID(f)
		if err != nil {
			return Scope{}, fmt.Errorf("--mcp-allow-uid: %w", err)
		}
		if !slices.Contains(s.UIDs, uid) {
			s.UIDs = append(s.UIDs, uid)
		}
	}
	for _, f := range splitList(cgroups) {
		p, _, err := bpf.ResolveCgroupSpec(f)
		if err != nil {
			return Scope{}, fmt.Errorf("--mcp-allow-cgroup %s: %w", f, err)
		}
		if !slices.Contains(s.Cgroups, p) {
			s.Cgroups = append(s.Cgroups, p)
		}
	}
	if !s.Any && len(s.UIDs) == 0 && len(s.Cgroups) == 0 {
		return Scope{}, errors.New("--mcp needs a scope: --mcp-allow-uid <uids>, --mcp-allow-cgroup <paths>, or --mcp-allow-any for every process on the host")
	}
	return s, nil
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func parseUID(s string) (uint32, error) {
	if n, err := strconv.ParseUint(s, 10, 32); err == nil {
		return uint32(n), nil
	}
	u, err := user.Lookup(s)
	if err != nil {
		return 0, fmt.Errorf("%q is neither a uid nor a user: %w", s, err)
	}
	n, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("user %q has a uid that is not a number: %q", s, u.Uid)
	}
	return uint32(n), nil
}

// String says what the scope allows, in the words a tool description uses.
func (s Scope) String() string {
	if s.Any {
		return "any process on this host"
	}
	var parts []string
	if len(s.UIDs) > 0 {
		ids := make([]string, len(s.UIDs))
		for i, u := range s.UIDs {
			ids[i] = strconv.FormatUint(uint64(u), 10)
		}
		parts = append(parts, "processes running only as uid "+strings.Join(ids, " or "))
	}
	if len(s.Cgroups) > 0 {
		parts = append(parts, "processes and cgroups under "+strings.Join(s.Cgroups, ", "))
	}
	return strings.Join(parts, "; and ")
}

// AllowPID says whether a capture of pid is in scope, and if not, why.
func (s Scope) AllowPID(pid int) error {
	if s.Any {
		return nil
	}
	var seen []string
	if len(s.UIDs) > 0 {
		uids, err := s.lookupUIDs(pid)
		switch {
		case err != nil:
			seen = append(seen, fmt.Sprintf("uids unreadable: %v", err))
		case allIn(uids, s.UIDs):
			return nil
		default:
			seen = append(seen, "uids "+formatUIDs(uids))
		}
	}
	if len(s.Cgroups) > 0 {
		cg, err := s.lookupCgroup(pid)
		switch {
		case err != nil:
			seen = append(seen, fmt.Sprintf("cgroup unreadable: %v", err))
		case s.underAllowed(cg):
			return nil
		default:
			seen = append(seen, "cgroup "+cg)
		}
	}
	return fmt.Errorf("pid %d is outside this server's scope (%s): it captures %s",
		pid, strings.Join(seen, "; "), s)
}

// AllowCgroup says whether a capture of the cgroup at path (absolute, as
// bpf.ResolveCgroupSpec returns it) is in scope. A uid rule never allows one:
// a subtree may hold any user's processes.
func (s Scope) AllowCgroup(p string) error {
	if s.Any || s.underAllowed(p) {
		return nil
	}
	return fmt.Errorf("cgroup %s is outside this server's scope: it captures %s", p, s)
}

func (s Scope) underAllowed(p string) bool {
	p = path.Clean(p)
	for _, root := range s.Cgroups {
		root = path.Clean(root)
		if p == root || strings.HasPrefix(p, root+"/") {
			return true
		}
	}
	return false
}

func (s Scope) lookupUIDs(pid int) ([]uint32, error) {
	if s.uidsOf != nil {
		return s.uidsOf(pid)
	}
	return processUIDs(pid)
}

func (s Scope) lookupCgroup(pid int) (string, error) {
	if s.cgroupOf != nil {
		return s.cgroupOf(pid)
	}
	return bpf.CgroupOfPID(pid)
}

func allIn(uids, allowed []uint32) bool {
	if len(uids) == 0 {
		return false
	}
	for _, u := range uids {
		if !slices.Contains(allowed, u) {
			return false
		}
	}
	return true
}

func formatUIDs(uids []uint32) string {
	parts := make([]string, len(uids))
	for i, u := range uids {
		parts[i] = strconv.FormatUint(uint64(u), 10)
	}
	return strings.Join(parts, "/")
}
