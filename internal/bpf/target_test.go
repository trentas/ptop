//go:build linux && ebpf

package bpf

import (
	"os"
	"strings"
	"testing"
	"unsafe"
)

// The Go targetFilter must match `struct target_filter` in target.bpf.h
// byte-for-byte, or the loader writes garbage into the BPF map. Size alone
// is not enough — field offsets must match too, since the kernel reads the
// struct verbatim.
func TestTargetFilterLayout(t *testing.T) {
	var tf targetFilter
	if got := unsafe.Sizeof(tf); got != 40 {
		t.Fatalf("sizeof(targetFilter) = %d, want 40", got)
	}
	offsets := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"Mode", unsafe.Offsetof(tf.Mode), 4},
		{"Dev", unsafe.Offsetof(tf.Dev), 8},
		{"Ino", unsafe.Offsetof(tf.Ino), 16},
		{"CgroupID", unsafe.Offsetof(tf.CgroupID), 24},
		{"CgroupLevel", unsafe.Offsetof(tf.CgroupLevel), 32},
	}
	for _, o := range offsets {
		if o.got != o.want {
			t.Errorf("offsetof(targetFilter.%s) = %d, want %d", o.name, o.got, o.want)
		}
	}
}

func TestResolveTargetSelf(t *testing.T) {
	tf, err := resolveTarget(TargetPID(os.Getpid()))
	if err != nil {
		t.Fatalf("resolveTarget(self): %v", err)
	}
	if tf.Mode != targetModePID {
		t.Errorf("Mode = %d, want PID mode", tf.Mode)
	}
	if tf.Pid != uint32(os.Getpid()) {
		t.Errorf("Pid = %d, want %d", tf.Pid, os.Getpid())
	}
	if tf.Dev == 0 {
		t.Error("Dev = 0, want the nsfs device number")
	}
	if tf.Ino == 0 {
		t.Error("Ino = 0, want the pid-namespace inode")
	}
}

func TestResolveTargetMissingPID(t *testing.T) {
	// 0x7fffffff exceeds Linux's hard cap on pid_max (PID_MAX_LIMIT = 4194304),
	// so this PID is guaranteed not to exist on any kernel.
	if _, err := resolveTarget(TargetPID(0x7fffffff)); err == nil {
		t.Error("resolveTarget(nonexistent pid) = nil error, want failure")
	}
}

// Cgroup mode against this process's own cgroup: the resolved filter must name
// a real cgroup below the root. Skipped where there is nothing to resolve — a
// cgroup v1-only host, or a cgroup namespace that shows "/" as its own root.
func TestResolveTargetSelfCgroup(t *testing.T) {
	mi, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Skipf("no mountinfo: %v", err)
	}
	root, err := cgroup2Root(string(mi))
	if err != nil {
		t.Skipf("no cgroup2 hierarchy: %v", err)
	}

	self, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Skipf("no /proc/self/cgroup: %v", err)
	}
	spec := ""
	for _, line := range strings.Split(string(self), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			spec = strings.TrimSpace(rest)
			break
		}
	}
	if spec == "" || spec == "/" {
		t.Skipf("this process sees its cgroup as %q — nothing below the root to target", spec)
	}

	tf, err := resolveTarget(TargetCgroup(spec))
	if err != nil {
		t.Fatalf("resolveTarget(cgroup %s): %v", spec, err)
	}
	if tf.Mode != targetModeCgroup {
		t.Errorf("Mode = %d, want cgroup mode", tf.Mode)
	}
	if tf.CgroupID == 0 {
		t.Error("CgroupID = 0, want the cgroup directory inode")
	}
	if tf.CgroupLevel == 0 {
		t.Error("CgroupLevel = 0, which is the cgroup root — the resolver should have refused it")
	}
	if tf.Pid != 0 || tf.Dev != 0 || tf.Ino != 0 {
		t.Errorf("pid-mode fields set in a cgroup target: %+v", tf)
	}

	// The root itself must be refused: it would trace every process on the host.
	if _, err := resolveTarget(TargetCgroup(root)); err == nil {
		t.Error("resolveTarget(cgroup root) = nil error, want a refusal")
	}
}
