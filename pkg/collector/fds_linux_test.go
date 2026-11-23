//go:build linux

package collector

import (
	"os"
	"syscall"
	"testing"
)

// TestReadFDLimitMatchesGetrlimit reads this process's limit through /proc, as
// the collector reads the target's, and checks it against the kernel's answer.
func TestReadFDLimitMatchesGetrlimit(t *testing.T) {
	var want syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &want); err != nil {
		t.Fatalf("getrlimit: %v", err)
	}
	got, ok := readFDLimit(os.Getpid())
	if !ok {
		t.Fatal("readFDLimit: no limit read from /proc/self/limits")
	}
	if got.Soft != want.Cur || got.Hard != want.Max {
		t.Fatalf("readFDLimit = %+v, getrlimit = {Soft:%d Hard:%d}", got, want.Cur, want.Max)
	}
}
