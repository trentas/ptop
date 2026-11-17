//go:build linux && ebpf

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/trentas/ptop/internal/bpf"
)

// ─── cgroupns: the cgroup filter from inside a cgroup namespace (#193) ─────
//
// A container sees its own cgroup as the root of the hierarchy: its cgroup
// namespace starts there, and the cgroup2 it mounts shows that cgroup as `/`.
// The filter used to match by a depth counted from that mount's root, and the
// kernel counts from the host's root, so from inside a namespace it named the
// wrong ancestor and every axis read zero. CI's runners are not nested, so the
// case builds the nesting itself, the way a container runtime does:
//
//	host:  /  →  ptop-selftest-ns-<pid>  →  inner
//	child:        /                      →  /inner
//
// The child is this binary re-executed, born in the outer cgroup
// (CLONE_INTO_CGROUP) with a cgroup and a mount namespace of its own. It
// mounts cgroup2, moves itself into `inner`, targets `/inner` the way
// `--cgroup` would, and counts its own getppid calls. The old filter computed
// level 1 there and compared `inner`'s id with `ptop-selftest-ns-<pid>`'s.

// cgroupNSCalls is how many getppid calls the child plants. Nothing else in
// the child calls getppid, so the count is exact.
const cgroupNSCalls = 2000

// cgroupNSResult is the child's report, one JSON line on its stdout.
type cgroupNSResult struct {
	View    string `json:"view"`
	Getppid uint64 `json:"getppid"`
	Err     string `json:"error,omitempty"`
}

func checkCgroupNS(g *grader, _ int) {
	const axis = "cgroupns"
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		g.skip(axis, "the cgroup filter inside a cgroup namespace", "no cgroup v2 hierarchy mounted at /sys/fs/cgroup")
		return
	}
	outer := fmt.Sprintf("/sys/fs/cgroup/ptop-selftest-ns-%d", os.Getpid())
	if err := os.Mkdir(outer, 0o755); err != nil {
		g.broken(axis, "create the namespace's root cgroup", err)
		return
	}
	defer removeCgroups(filepath.Join(outer, "inner"), outer)
	dir, err := os.Open(outer)
	if err != nil {
		g.broken(axis, "open the namespace's root cgroup", err)
		return
	}
	defer dir.Close()

	child := peerCmd("cgroupns")
	child.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD:  true,
		CgroupFD:     int(dir.Fd()),
		Unshareflags: syscall.CLONE_NEWCGROUP | syscall.CLONE_NEWNS,
	}
	out, runErr := child.Output()
	var res cgroupNSResult
	if err := json.Unmarshal(out, &res); err != nil {
		g.broken(axis, "run the child", fmt.Errorf("exit %v, output %q: %w", runErr, out, err))
		return
	}
	if res.Err != "" {
		g.broken(axis, "the child's setup", errors.New(res.Err))
		return
	}
	g.note(axis, "the child is in %s/inner; it sees %s", outer, res.View)
	g.check(axis, "the child sees its cgroup one level below its namespace's root",
		res.View == "/inner", "/inner", res.View)
	g.check(axis, "the cgroup filter counts the child's getppid calls, from inside its namespace",
		res.Getppid == cgroupNSCalls, strconv.Itoa(cgroupNSCalls), strconv.FormatUint(res.Getppid, 10))
}

// runCgroupNSChild is the child side. It reports on stdout and exits.
func runCgroupNSChild() {
	var res cgroupNSResult
	report := func(code int) {
		_ = json.NewEncoder(os.Stdout).Encode(res)
		os.Exit(code)
	}
	fail := func(step string, err error) {
		res.Err = step + ": " + err.Error()
		report(1)
	}

	// Mounted from inside the namespace, cgroup2's root is the namespace's.
	// The mount inherited from the parent goes first: the kernel refuses a
	// filesystem mounted on top of its own root (EBUSY). The mount namespace
	// is the child's own, so nothing outside it changes.
	if err := unix.Unmount("/sys/fs/cgroup", unix.MNT_DETACH); err != nil {
		fail("unmount the inherited cgroup2", err)
	}
	if err := unix.Mount("cgroup2", "/sys/fs/cgroup", "cgroup2", 0, ""); err != nil {
		fail("mount cgroup2", err)
	}
	if err := os.Mkdir("/sys/fs/cgroup/inner", 0o755); err != nil {
		fail("create /inner", err)
	}
	if err := os.WriteFile("/sys/fs/cgroup/inner/cgroup.procs", []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
		fail("move into /inner", err)
	}
	view, why := selfCgroup()
	if view == "" {
		fail("read the child's cgroup", errors.New(why))
	}
	res.View = view

	t, err := bpf.OpenSyscallTracer(bpf.TargetCgroup(view))
	if err != nil {
		fail("OpenSyscallTracer(cgroup "+view+")", err)
	}
	for i := 0; i < cgroupNSCalls; i++ {
		_ = unix.Getppid()
	}
	stats, err := t.Stats()
	t.Close()
	if err != nil {
		fail("read the syscall counts", err)
	}
	res.Getppid = stats[unix.SYS_GETPPID].Count
	report(0)
}

// removeCgroups removes each cgroup in turn, deepest first. A child just
// reaped can hold its cgroup for a moment longer, so each gets a second.
func removeCgroups(dirs ...string) {
	for _, d := range dirs {
		for deadline := time.Now().Add(time.Second); ; time.Sleep(20 * time.Millisecond) {
			err := os.Remove(d)
			if err == nil || errors.Is(err, os.ErrNotExist) || time.Now().After(deadline) {
				break
			}
		}
	}
}
