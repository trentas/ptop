//go:build linux

package collector

import (
	"os"
	"testing"
	"time"
)

// TestProcContextCollectorLive exercises the real /proc reading path against
// the test process itself (CI-only — the file is linux-tagged). The parsers are
// unit-tested separately in proccontext_test.go; this proves the glue and the
// namespace readlinks actually work on a live pid.
func TestProcContextCollectorLive(t *testing.T) {
	c := NewProcContextCollector()
	if err := c.Start(os.Getpid()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Stop()

	select {
	case v := <-c.Subscribe():
		pc, ok := v.(ProcContext)
		if !ok {
			t.Fatalf("got %T, want ProcContext", v)
		}
		if pc.UID != uint32(os.Getuid()) {
			t.Errorf("UID = %d, want %d", pc.UID, os.Getuid())
		}
		if pc.GID != uint32(os.Getgid()) {
			t.Errorf("GID = %d, want %d", pc.GID, os.Getgid())
		}
		// /proc/self/ns/pid is always readable for the caller, so its inode
		// must resolve to a non-zero value.
		if pc.PIDNS == 0 {
			t.Errorf("PIDNS = 0, want a namespace inode")
		}
		if pc.Timestamp.IsZero() {
			t.Errorf("Timestamp is zero")
		}
		// The test binary started moments ago. btime has one-second
		// resolution, so the reading may land up to a second early.
		if age := time.Since(pc.StartTime); pc.StartTime.IsZero() || age < -2*time.Second || age > 5*time.Minute {
			t.Errorf("StartTime = %v (%v ago), want this test process's start", pc.StartTime, age)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no ProcContext published within 2s")
	}
}
