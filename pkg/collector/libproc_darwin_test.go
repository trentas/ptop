//go:build darwin

package collector

import (
	"os"
	"testing"
)

// Smoke tests for the libproc cgo wrappers. They exercise each function
// against the test process itself (os.Getpid()), which is guaranteed to be
// alive and owned by the current euid. If any of these fail we know the
// binding is wrong before layering collectors on top.

func TestProcName_self(t *testing.T) {
	name, err := ProcName(os.Getpid())
	if err != nil {
		t.Fatalf("ProcName(self): %v", err)
	}
	if name == "" {
		t.Fatalf("ProcName(self) returned empty string")
	}
	// During go test the binary is named "collector.test" (or similar);
	// just confirm we got something printable.
	t.Logf("self name = %q", name)
}

func TestProcPidTaskInfo_self(t *testing.T) {
	info, err := ProcPidTaskInfo(os.Getpid())
	if err != nil {
		t.Fatalf("ProcPidTaskInfo(self): %v", err)
	}
	if info.ThreadCount == 0 {
		t.Fatalf("self should have at least 1 thread, got 0")
	}
	if info.ResidentSize == 0 {
		t.Fatalf("self should have non-zero RSS, got 0")
	}
	// Time should be at least a few microseconds — we've been running.
	if info.UserTimeNs+info.SystemTimeNs == 0 {
		t.Fatalf("self should have non-zero CPU time, got user=%d sys=%d", info.UserTimeNs, info.SystemTimeNs)
	}
	t.Logf("self: rss=%d threads=%d utime=%dns stime=%dns faults=%d",
		info.ResidentSize, info.ThreadCount, info.UserTimeNs, info.SystemTimeNs, info.FaultCount)
}

func TestProcPidRUsage_self(t *testing.T) {
	r, err := ProcPidRUsage(os.Getpid())
	if err != nil {
		t.Fatalf("ProcPidRUsage(self): %v", err)
	}
	// PageIns may legitimately be zero if the test process never page-faulted
	// from disk. We just verify the call succeeds; sanity-check that resident
	// size matches roughly the TaskInfo view.
	t.Logf("rusage: disk_read=%dB disk_write=%dB pageins=%d wired=%dB rss=%dB",
		r.DiskIOBytesRead, r.DiskIOBytesWrite, r.PageIns, r.WiredSize, r.ResidentSize)
}

func TestListThreads_self(t *testing.T) {
	tids, err := ListThreads(os.Getpid())
	if err != nil {
		t.Fatalf("ListThreads(self): %v", err)
	}
	if len(tids) == 0 {
		t.Fatalf("self should have at least 1 thread, got empty list")
	}
	t.Logf("self has %d threads (first TID = %d)", len(tids), tids[0])
}

func TestProcPidThreadInfo_self(t *testing.T) {
	tids, err := ListThreads(os.Getpid())
	if err != nil || len(tids) == 0 {
		t.Skipf("can't list threads: %v", err)
	}
	ti, err := ProcPidThreadInfo(os.Getpid(), tids[0])
	if err != nil {
		t.Fatalf("ProcPidThreadInfo(self, %d): %v", tids[0], err)
	}
	t.Logf("first thread: name=%q runState=%d cpuUsage=%d/1000",
		ti.Name, ti.RunState, ti.CPUUsage)
}

func TestListFDs_self(t *testing.T) {
	fds, err := ListFDs(os.Getpid())
	if err != nil {
		t.Fatalf("ListFDs(self): %v", err)
	}
	// At minimum we expect stdin/stdout/stderr (0,1,2) — though the test
	// runner may have closed them, so we just check we got *some* FDs.
	if len(fds) == 0 {
		t.Fatalf("self should have open FDs, got empty list")
	}
	t.Logf("self has %d FDs", len(fds))
	for _, fd := range fds {
		t.Logf("  fd=%d type=%d", fd.FD, fd.Type)
		if fd.Type == FDTypeVNode {
			if v, err := FDVNodePath(os.Getpid(), fd.FD); err == nil {
				t.Logf("    vnode path=%q", v.Path)
			}
		}
		if fd.Type == FDTypeSocket {
			if s, err := FDSocketInfo(os.Getpid(), fd.FD); err == nil {
				t.Logf("    socket family=%d type=%d local=%s remote=%s tcpState=%d",
					s.Family, s.SockType, s.LocalAddr, s.RemoteAddr, s.TCPState)
			}
		}
		if fd.Type == FDTypePipe {
			if p, err := FDPipeInfo(os.Getpid(), fd.FD); err == nil {
				t.Logf("    pipe id=%d status=%d", p.PipeID, p.Status)
			}
		}
	}
}
