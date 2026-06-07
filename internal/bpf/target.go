//go:build linux && ebpf

package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// targetFilter mirrors `struct target_filter` in programs/target.bpf.h
// byte-for-byte (24 bytes: u32 pid, u32 pad, u64 dev, u64 ino).
type targetFilter struct {
	Pid uint32
	_   uint32
	Dev uint64
	Ino uint64
}

// resolveTarget builds the filter for pid: its tgid plus the device and
// inode of the PID namespace it lives in (/proc/<pid>/ns/pid).
//
// On a native host in the root namespace this resolves to the initial PID
// namespace, so the BPF-side bpf_get_ns_current_pid_tgid() call returns the
// same values bpf_get_current_pid_tgid() returned before — identical
// behavior. Inside a nested namespace (WSL2, containers) it resolves to that
// namespace, which is what makes the filter match.
func resolveTarget(pid int) (targetFilter, error) {
	var st unix.Stat_t
	if err := unix.Stat(fmt.Sprintf("/proc/%d/ns/pid", pid), &st); err != nil {
		return targetFilter{}, fmt.Errorf("stat pid namespace of %d: %w", pid, err)
	}
	return targetFilter{Pid: uint32(pid), Dev: st.Dev, Ino: st.Ino}, nil
}

// writeTargetFilter stores the resolved filter at key 0 of an ARRAY[1] map.
func writeTargetFilter(m *ebpf.Map, tf targetFilter) error {
	var key uint32 = 0
	return m.Update(&key, &tf, ebpf.UpdateAny)
}
