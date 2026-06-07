//go:build linux && ebpf

package bpf

import (
	"os"
	"testing"
	"unsafe"
)

// The Go targetFilter must match `struct target_filter` in target.bpf.h
// byte-for-byte, or the loader writes garbage into the BPF map. Size alone
// is not enough — field offsets must match too, since the kernel reads the
// struct verbatim.
func TestTargetFilterLayout(t *testing.T) {
	var tf targetFilter
	if got := unsafe.Sizeof(tf); got != 24 {
		t.Fatalf("sizeof(targetFilter) = %d, want 24", got)
	}
	if got := unsafe.Offsetof(tf.Dev); got != 8 {
		t.Fatalf("offsetof(targetFilter.Dev) = %d, want 8", got)
	}
	if got := unsafe.Offsetof(tf.Ino); got != 16 {
		t.Fatalf("offsetof(targetFilter.Ino) = %d, want 16", got)
	}
}

func TestResolveTargetSelf(t *testing.T) {
	tf, err := resolveTarget(os.Getpid())
	if err != nil {
		t.Fatalf("resolveTarget(self): %v", err)
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
	if _, err := resolveTarget(0x7fffffff); err == nil {
		t.Error("resolveTarget(nonexistent pid) = nil error, want failure")
	}
}
