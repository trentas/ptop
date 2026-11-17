package mcp

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestParseScopeNeedsOne(t *testing.T) {
	if _, err := ParseScope(false, "", ""); err == nil || !strings.Contains(err.Error(), "--mcp-allow-any") {
		t.Errorf("no scope = %v, want an error naming the three flags", err)
	}
	if _, err := ParseScope(false, " , ", ""); err == nil {
		t.Error("a list of nothing was taken for a scope")
	}
	if _, err := ParseScope(true, "1000", ""); err == nil {
		t.Error("--mcp-allow-any with --mcp-allow-uid was accepted: one of them is not doing anything")
	}
	if _, err := ParseScope(false, "no-such-user-ptop-187", ""); err == nil {
		t.Error("an unknown user name was accepted")
	}
	s, err := ParseScope(false, "1000, 0,1000", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.UIDs) != 2 || s.UIDs[0] != 1000 || s.UIDs[1] != 0 {
		t.Errorf("UIDs = %v, want [1000 0]", s.UIDs)
	}
	s, err = ParseScope(false, "root", "")
	if err != nil {
		t.Fatalf("a user name: %v", err)
	}
	if len(s.UIDs) != 1 || s.UIDs[0] != 0 {
		t.Errorf("root = %v, want uid 0", s.UIDs)
	}
}

func fakeScope(uids []uint32, cgroups []string, procUIDs []uint32, procCgroup string) Scope {
	return Scope{
		UIDs: uids, Cgroups: cgroups,
		uidsOf: func(int) ([]uint32, error) {
			if procUIDs == nil {
				return nil, errors.New("gone")
			}
			return procUIDs, nil
		},
		cgroupOf: func(int) (string, error) {
			if procCgroup == "" {
				return "", errors.New("gone")
			}
			return procCgroup, nil
		},
	}
}

func TestScopeAllowPID(t *testing.T) {
	const svc = "/sys/fs/cgroup/system.slice/app.service"
	cases := []struct {
		name  string
		scope Scope
		allow bool
	}{
		{"every uid allowed", fakeScope([]uint32{1000}, nil, []uint32{1000, 1000, 1000, 1000}, ""), true},
		// A setuid program started by an allowed user runs as someone else.
		{"effective uid is root", fakeScope([]uint32{1000}, nil, []uint32{1000, 0, 0, 0}, ""), false},
		{"another user", fakeScope([]uint32{1000}, nil, []uint32{33, 33, 33, 33}, ""), false},
		{"uids unreadable", fakeScope([]uint32{1000}, nil, nil, ""), false},
		{"in the cgroup", fakeScope(nil, []string{svc}, nil, svc), true},
		{"below the cgroup", fakeScope(nil, []string{svc}, nil, svc+"/worker"), true},
		// A path prefix is not a subtree.
		{"a sibling sharing the prefix", fakeScope(nil, []string{svc}, nil, svc+"-canary"), false},
		{"cgroup unreadable", fakeScope(nil, []string{svc}, nil, ""), false},
		// Either rule allows.
		{"uid fails, cgroup allows", fakeScope([]uint32{1000}, []string{svc}, []uint32{0, 0, 0, 0}, svc), true},
		{"cgroup fails, uid allows", fakeScope([]uint32{0}, []string{svc}, []uint32{0, 0, 0, 0}, "/sys/fs/cgroup/user.slice"), true},
		{"any", Scope{Any: true}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.scope.AllowPID(4242)
			if (err == nil) != c.allow {
				t.Fatalf("AllowPID = %v, want allowed %v", err, c.allow)
			}
			// A refusal says what it saw and what the server captures, so the
			// agent does not retry blind.
			if err != nil && (!strings.Contains(err.Error(), "4242") || !strings.Contains(err.Error(), "it captures")) {
				t.Errorf("refusal %q does not name the pid and the scope", err)
			}
		})
	}
}

func TestScopeAllowCgroup(t *testing.T) {
	const svc = "/sys/fs/cgroup/system.slice/app.service"
	s := fakeScope([]uint32{0}, []string{svc}, nil, "")
	for p, allow := range map[string]bool{
		svc:                    true,
		svc + "/worker":        true,
		svc + "-canary":        false,
		"/sys/fs/cgroup":       false,
		"/sys/fs/cgroup/other": false,
	} {
		if err := s.AllowCgroup(p); (err == nil) != allow {
			t.Errorf("AllowCgroup(%s) = %v, want allowed %v", p, err, allow)
		}
	}
	// A uid rule never covers a subtree: it may hold anyone's processes.
	if err := fakeScope([]uint32{0}, nil, nil, "").AllowCgroup(svc); err == nil {
		t.Error("a uid-only scope allowed a cgroup target")
	}
}

func TestScopeString(t *testing.T) {
	if got := (Scope{Any: true}).String(); got != "any process on this host" {
		t.Errorf("any = %q", got)
	}
	got := Scope{UIDs: []uint32{1000, 33}, Cgroups: []string{"/sys/fs/cgroup/a"}}.String()
	if !strings.Contains(got, "uid 1000 or 33") || !strings.Contains(got, "/sys/fs/cgroup/a") {
		t.Errorf("String = %q, want both rules", got)
	}
}

// The real lookup, against this process.
func TestProcessUIDsSelf(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("no uid lookup on " + runtime.GOOS)
	}
	uids, err := processUIDs(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if len(uids) < 3 {
		t.Fatalf("uids = %v, want real, effective and saved at least", uids)
	}
	for _, u := range uids {
		if u != uint32(os.Getuid()) {
			t.Errorf("uids = %v, want every one %d", uids, os.Getuid())
		}
	}
}
