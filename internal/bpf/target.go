//go:build linux && ebpf

package bpf

import (
	"fmt"
	"os"
	"path"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// targetFilter mirrors `struct target_filter` in programs/target.bpf.h
// byte-for-byte (24 bytes: u32 pid, u32 mode, u64 dev, u64 ino).
type targetFilter struct {
	Pid  uint32
	Mode uint32
	Dev  uint64
	Ino  uint64
}

// targetCgroupMap is the CGROUP_ARRAY every program that includes
// target.bpf.h declares: in cgroup mode, slot 0 holds the target cgroup.
const targetCgroupMap = "ptop_target_cgroup"

// resolvedTarget is a Target resolved for a loader: the filter the programs
// read and, in cgroup mode, the cgroup that goes into targetCgroupMap.
type resolvedTarget struct {
	targetFilter

	// CgroupDir is the target cgroup's directory, and CgroupID its inode when
	// it was resolved: the directory is opened again to fill the map, and a
	// cgroup replaced in between is refused rather than traced.
	CgroupDir string
	CgroupID  uint64
}

// resolveTarget builds what the BPF programs read, for either way of naming a
// target (see Target).
func resolveTarget(t Target) (resolvedTarget, error) {
	if t.IsCgroup() {
		return resolveCgroupTarget(t.Cgroup)
	}
	tf, err := resolvePIDTarget(t.PID)
	return resolvedTarget{targetFilter: tf}, err
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
		return targetFilter{}, targetReadError(fmt.Sprintf("stat pid namespace of %d", pid), err)
	}
	return targetFilter{Mode: targetModePID, Pid: uint32(pid), Dev: st.Dev, Ino: st.Ino}, nil
}

// resolveCgroupTarget resolves a cgroup spec (path or container id) to the
// cgroup's directory and id.
//
// The id is the cgroup directory's inode number: since kernel 5.5 kernfs node
// ids are 64-bit inodes, and that is exactly the value
// bpf_get_current_cgroup_id() reports.
func resolveCgroupTarget(spec string) (resolvedTarget, error) {
	p, id, err := ResolveCgroupSpec(spec)
	if err != nil {
		return resolvedTarget{}, err
	}
	return resolvedTarget{
		targetFilter: targetFilter{Mode: targetModeCgroup},
		CgroupDir:    p,
		CgroupID:     id,
	}, nil
}

// ResolveCgroupSpec resolves a cgroup spec to the absolute cgroup path it names
// and that cgroup's id. Exported so the CLI can resolve once up front — failing
// before any tracer is loaded, reporting what a container id actually matched,
// and then handing the unambiguous path to every collector.
func ResolveCgroupSpec(spec string) (path string, id uint64, err error) {
	mi, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", 0, fmt.Errorf("read mountinfo: %w", err)
	}
	root, err := cgroup2Root(string(mi))
	if err != nil {
		return "", 0, err
	}

	p, err := cgroupPath(os.DirFS(root), root, spec)
	if err != nil {
		return "", 0, err
	}

	level, err := cgroupLevel(root, p)
	if err != nil {
		return "", 0, err
	}
	if level == 0 {
		return "", 0, fmt.Errorf(
			"cgroup %q is the cgroup root — targeting it would trace every process on the host", p)
	}

	var st unix.Stat_t
	if err := unix.Stat(p, &st); err != nil {
		return "", 0, fmt.Errorf("stat cgroup %q: %w", p, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return "", 0, fmt.Errorf("cgroup %q is not a directory", p)
	}

	return p, st.Ino, nil
}

// writeTargetFilter configures coll's programs for rt: in cgroup mode the
// target cgroup first, then the filter at key 0 of m, an ARRAY[1], so no
// program reads cgroup mode with an empty slot.
func writeTargetFilter(coll *ebpf.Collection, m *ebpf.Map, rt resolvedTarget) error {
	if rt.Mode == targetModeCgroup {
		if err := writeTargetCgroup(coll.Maps[targetCgroupMap], rt); err != nil {
			return err
		}
	}
	var key uint32 = 0
	return m.Update(&key, &rt.targetFilter, ebpf.UpdateAny)
}

// writeTargetCgroup puts the target cgroup in slot 0 of the cgroup array, from
// an fd of its directory. The map holds the cgroup itself from then on, so the
// fd is closed again.
func writeTargetCgroup(m *ebpf.Map, rt resolvedTarget) error {
	if m == nil {
		return fmt.Errorf("%s map not found in BPF object", targetCgroupMap)
	}
	fd, err := unix.Open(rt.CgroupDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open cgroup %q: %w", rt.CgroupDir, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("stat cgroup %q: %w", rt.CgroupDir, err)
	}
	if st.Ino != rt.CgroupID {
		return fmt.Errorf("cgroup %q was replaced after it was resolved (id %d, now %d)",
			rt.CgroupDir, rt.CgroupID, st.Ino)
	}
	var key uint32 = 0
	val := uint32(fd)
	if err := m.Update(&key, &val, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("set %s: %w", targetCgroupMap, err)
	}
	return nil
}

// CgroupOfPID returns the cgroup v2 path pid is in, absolute and in the form
// ResolveCgroupSpec returns, so the two compare as paths (#187).
func CgroupOfPID(pid int) (string, error) {
	mi, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", fmt.Errorf("read mountinfo: %w", err)
	}
	root, err := cgroup2Root(string(mi))
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	rel, err := cgroupV2Rel(string(b))
	if err != nil {
		return "", fmt.Errorf("pid %d: %w", pid, err)
	}
	return path.Join(root, rel), nil
}
