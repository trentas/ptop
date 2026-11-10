//go:build linux

package serve

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/trentas/ptop/pkg/collector"
	pb "github.com/trentas/ptop/pkg/streampb"
)

// The machine this test runs on is the planted answer.
func TestHandshakeCarriesTheHost(t *testing.T) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		t.Skip(err)
	}
	ti := handshakeFor(t, TargetPID(os.Getpid()))
	h := ti.GetHost()
	if h.GetKernelRelease() != unix.ByteSliceToString(u.Release[:]) || h.GetMachine() != unix.ByteSliceToString(u.Machine[:]) {
		t.Errorf("host = %s on %s, uname says %s on %s", h.GetKernelRelease(), h.GetMachine(),
			unix.ByteSliceToString(u.Release[:]), unix.ByteSliceToString(u.Machine[:]))
	}
	if h.GetCpu().GetLogicalCpus() == 0 || h.GetCpu().GetVendor() == "" {
		t.Errorf("cpu = %v", h.GetCpu())
	}
	if h.GetVirtualization() == nil {
		t.Error("no virtualization verdict, not even unknown")
	}

	cg, err := collector.CgroupOf(os.Getpid())
	if err != nil {
		t.Skip(err)
	}
	if got := ti.GetLimits().GetCgroup(); got != cg {
		t.Errorf("limits read from %q, this process is in %q", got, cg)
	}
}

// In cgroup mode the limits are the target cgroup's, named the way
// /proc/<pid>/cgroup would name it.
func TestCgroupHandshakeLimitsAreTheTargets(t *testing.T) {
	cg, err := collector.CgroupOf(os.Getpid())
	if err != nil || cg == "" {
		t.Skip("no cgroup to target")
	}
	ti := NewHub(TargetCgroup("/sys/fs/cgroup"+cg, 1), "", nil).targetInfo()
	if ti.GetMode() != pb.TargetMode_TARGET_MODE_CGROUP || ti.GetLimits().GetCgroup() != cg {
		t.Errorf("cgroup handshake limits from %q, want %q", ti.GetLimits().GetCgroup(), cg)
	}
	if ti.GetHost() == nil {
		t.Error("cgroup mode carries no host; the machine is the same whatever the scope")
	}
}
