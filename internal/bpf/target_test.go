//go:build linux && ebpf

package bpf

import (
	"os"
	"testing"
	"unsafe"
)

// The Go targetFilter must match `struct target_filter` in target.bpf.h
// byte-for-byte, or the loader writes garbage into the BPF map.
func TestTargetFilterSize(t *testing.T) {
	if got := unsafe.Sizeof(targetFilter{}); got != 24 {
		t.Fatalf("sizeof(targetFilter) = %d, want 24", got)
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
	if _, err := resolveTarget(0x7fffffff); err == nil {
		t.Error("resolveTarget(nonexistent pid) = nil error, want failure")
	}
}
