//go:build linux && ebpf

package bpf

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// targetFilter mirrors `struct target_filter` in programs/target.bpf.h
// byte-for-byte (40 bytes: u32 pid, u32 mode, u64 dev, u64 ino, u64 cgroup_id,
// u32 cgroup_level, u32 pad).
type targetFilter struct {
	Pid         uint32
	Mode        uint32
	Dev         uint64
	Ino         uint64
	CgroupID    uint64
	CgroupLevel uint32
	_           uint32
}

// resolveTarget builds the filter the BPF programs read, for either way of
// naming a target (see Target).
func resolveTarget(t Target) (targetFilter, error) {
	if t.IsCgroup() {
		return resolveCgroupTarget(t.Cgroup)
	}
	return resolvePIDTarget(t.PID)
}

// resolvePIDTarget builds the filter for pid: its tgid plus the device and
// inode of the PID namespace it lives in (/proc/<pid>/ns/pid).
//
// On a native host in the root namespace this resolves to the initial PID
// namespace, so the BPF-side bpf_get_ns_current_pid_tgid() call returns the
// same values bpf_get_current_pid_tgid() returned before — identical
// behavior. Inside a nested namespace (WSL2, containers) it resolves to that
// namespace, which is what makes the filter match.
func resolvePIDTarget(pid int) (targetFilter, error) {
	var st unix.Stat_t
	if err := unix.Stat(fmt.Sprintf("/proc/%d/ns/pid", pid), &st); err != nil {
		return targetFilter{}, fmt.Errorf("stat pid namespace of %d: %w", pid, err)
	}
	return targetFilter{Mode: targetModePID, Pid: uint32(pid), Dev: st.Dev, Ino: st.Ino}, nil
}

// resolveCgroupTarget resolves a cgroup spec (path or container id) to the
// cgroup's id and its depth below the cgroup root, which is what
// bpf_get_current_ancestor_cgroup_id() needs to match a whole subtree.
//
// The id is the cgroup directory's inode number: since kernel 5.5 kernfs node
// ids are 64-bit inodes, and that is exactly the value
// bpf_get_current_cgroup_id() reports.
func resolveCgroupTarget(spec string) (targetFilter, error) {
	mi, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return targetFilter{}, fmt.Errorf("read mountinfo: %w", err)
	}
	root, err := cgroup2Root(string(mi))
	if err != nil {
		return targetFilter{}, err
	}

	p, err := cgroupPath(os.DirFS(root), root, spec)
	if err != nil {
		return targetFilter{}, err
	}

	level, err := cgroupLevel(root, p)
	if err != nil {
		return targetFilter{}, err
	}
	if level == 0 {
		return targetFilter{}, fmt.Errorf(
			"cgroup %q is the cgroup root — targeting it would trace every process on the host", p)
	}

	var st unix.Stat_t
	if err := unix.Stat(p, &st); err != nil {
		return targetFilter{}, fmt.Errorf("stat cgroup %q: %w", p, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return targetFilter{}, fmt.Errorf("cgroup %q is not a directory", p)
	}

	return targetFilter{Mode: targetModeCgroup, CgroupID: st.Ino, CgroupLevel: level}, nil
}

// writeTargetFilter stores the resolved filter at key 0 of an ARRAY[1] map.
func writeTargetFilter(m *ebpf.Map, tf targetFilter) error {
	var key uint32 = 0
	return m.Update(&key, &tf, ebpf.UpdateAny)
}
