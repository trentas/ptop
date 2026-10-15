//go:build linux

package collector

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #140: the bootstrap of pre-existing connections resolved the target's socket
// inodes in /proc/net/tcp — the table of ptop's own network namespace. A
// Profiler container with `pid: host` and its own netns found every fd of a
// host process and none of its sockets, and the probe stayed ACTIVE publishing
// fan_out 0.

// procTree writes a fixture /proc with one socket table for the reader's own
// namespace (/proc/net/tcp) and another for the target's (/proc/<pid>/net/tcp).
func procTree(t *testing.T, pid int, readerInode, targetInode uint64) string {
	t.Helper()
	root := t.TempDir()
	table := func(inode uint64) string {
		return "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
			fmt.Sprintf("   0: 0100007F:1F90 0100007F:E96A 01 00000000:00000000 00:00000000 00000000  1000        0 %d 1 0000000000000000 100 0 0 10 0\n", inode)
	}
	for dir, inode := range map[string]uint64{
		filepath.Join(root, "net"):                  readerInode,
		filepath.Join(root, fmt.Sprint(pid), "net"): targetInode,
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := writeFileForTest(filepath.Join(dir, "tcp"), table(inode)); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestResolverReadsTheTargetsTables(t *testing.T) {
	r := NewSocketResolver()
	r.procRoot = procTree(t, 780, 11111, 55555)

	// Before ForPID — the reader's own namespace. This is what the bootstrap
	// used to read for every target.
	if _, ok := r.Resolve(55555); ok {
		t.Fatal("the target's socket resolved in the reader's own table — the fixture does not separate the two")
	}

	r.ForPID(780)
	info, ok := r.Resolve(55555)
	if !ok {
		t.Fatal("the target's socket did not resolve in /proc/<pid>/net/tcp — the seed would stay empty (#140)")
	}
	if info.Family != "TCP" || info.State != "ESTABLISHED" {
		t.Errorf("resolved %+v, want an ESTABLISHED TCP socket", info)
	}
	// ForPID must drop the cache, which held the reader's table: answering
	// from it would keep resolving sockets the target does not have.
	if _, ok := r.Resolve(11111); ok {
		t.Error("a socket of the reader's namespace still resolves after ForPID — the cache survived the switch")
	}
}

func TestResolverForPIDIgnoresNonPositive(t *testing.T) {
	// Cgroup scope has no single pid; its tables stay the reader's.
	r := NewSocketResolver()
	r.procRoot = procTree(t, 780, 11111, 55555)
	r.ForPID(0)
	if _, ok := r.Resolve(11111); !ok {
		t.Error("ForPID(0) moved the resolver off the reader's tables")
	}
}

func TestResolverResolvesOnTheRealProc(t *testing.T) {
	// The fixture proves the switch; this proves the path the kernel serves:
	// a listener this test owns, found by its inode in /proc/<pid>/net/tcp{,6}.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	defer ln.Close()
	f, err := ln.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	link, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", f.Fd()))
	if err != nil {
		t.Skipf("cannot read own fd: %v", err)
	}
	inode, ok := extractSocketInode(link)
	if !ok {
		t.Fatalf("fd link %q is not a socket", link)
	}

	r := NewSocketResolver()
	r.ForPID(os.Getpid())
	info, ok := r.Resolve(inode)
	if !ok {
		t.Fatalf("own listener (inode %d) not found in /proc/%d/net", inode, os.Getpid())
	}
	if info.State != "LISTEN" {
		t.Errorf("state %q, want LISTEN", info.State)
	}
}

func TestSeedCaveat(t *testing.T) {
	cases := []struct {
		name string
		rep  seedReport
		want string // substring; "" = no caveat at all
	}{
		{"fd dir unreadable", seedReport{fdErr: errors.New("permission denied")}, "reading /proc/780/fd failed (permission denied)"},
		{"nothing resolved", seedReport{sockets: 3}, "none of the target's 3 socket(s) is in /proc/780/net"},
		{"partly resolved", seedReport{sockets: 3, resolved: 1}, ""},
		{"all resolved", seedReport{sockets: 3, resolved: 3}, ""},
		{"no sockets", seedReport{}, ""},
	}
	for _, c := range cases {
		got := c.rep.caveat(780)
		if c.want == "" {
			if got != "" {
				t.Errorf("%s: caveat %q, want none — a partial count is routine (netlink, packet sockets)", c.name, got)
			}
			continue
		}
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: caveat %q, want it to contain %q", c.name, got, c.want)
		}
		if !strings.Contains(got, "fan_out") {
			t.Errorf("%s: caveat %q does not name the consequence a consumer would misread", c.name, got)
		}
	}
}
