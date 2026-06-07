//go:build darwin

package collector

import (
	"os"
	"testing"
	"time"
)

// Integration smoke tests for the darwin collectors that previously had no
// dedicated coverage. Each starts against this process and confirms a
// correctly-typed message arrives within a deadline. They exercise the real
// libproc path, not mocks.

// recvWithin reads one message from ch or fails after d.
func recvWithin(t *testing.T, ch <-chan interface{}, d time.Duration) interface{} {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(d):
		t.Fatalf("no message within %s", d)
		return nil
	}
}

func TestMemCollector_self(t *testing.T) {
	c := NewMemCollector()
	if err := c.Start(os.Getpid()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Stop()

	s, ok := recvWithin(t, c.Subscribe(), 3*time.Second).(MemStats)
	if !ok {
		t.Fatal("expected MemStats")
	}
	if s.RSSBytes == 0 {
		t.Fatalf("self should have non-zero RSS, got %+v", s)
	}
	t.Logf("mem: rss=%d faults=%d allocs/s=%d", s.RSSBytes, s.PageFaults, s.AllocsPerS)
}

func TestThreadsCollector_self(t *testing.T) {
	c := NewThreadsCollector()
	if err := c.Start(os.Getpid()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Stop()

	threads, ok := recvWithin(t, c.Subscribe(), 3*time.Second).([]ThreadInfo)
	if !ok {
		t.Fatal("expected []ThreadInfo")
	}
	if len(threads) == 0 {
		t.Fatal("self should have at least one thread")
	}
	// State labels must be the canonical strings the F4 view colors on.
	for _, th := range threads {
		switch th.State {
		case "running", "sleeping", "blocked", "stopped", "unknown":
		default:
			t.Fatalf("unexpected thread state label %q", th.State)
		}
	}
	t.Logf("threads: %d (first=%q state=%q)", len(threads), threads[0].Name, threads[0].State)
}

func TestIOThroughputCollector_self(t *testing.T) {
	c := NewIOThroughputCollector()
	if err := c.Start(os.Getpid()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Stop()

	s, ok := recvWithin(t, c.Subscribe(), 3*time.Second).(IOThroughputSample)
	if !ok {
		t.Fatal("expected IOThroughputSample")
	}
	if s.ReadBytesPerS < 0 || s.WriteBytesPerS < 0 {
		t.Fatalf("throughput must be non-negative, got %+v", s)
	}
	t.Logf("io throughput: r=%.0fB/s w=%.0fB/s", s.ReadBytesPerS, s.WriteBytesPerS)
}

func TestIOWaitCollector_self(t *testing.T) {
	c := NewIOWaitCollector()
	if err := c.Start(os.Getpid()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Stop()

	s, ok := recvWithin(t, c.Subscribe(), 3*time.Second).(IOWaitSample)
	if !ok {
		t.Fatal("expected IOWaitSample")
	}
	if s.Pct < 0 || s.Pct > 100 {
		t.Fatalf("iowait %% out of range: %v", s.Pct)
	}
	t.Logf("iowait: %.1f%%", s.Pct)
}

func TestFDCollector_self(t *testing.T) {
	c := NewFDCollector()
	if err := c.Start(os.Getpid()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Stop()

	// The collector emits FDEvent / TimelineEvent as well as the []FDEntry
	// snapshot; loop until the snapshot arrives.
	deadline := time.After(3 * time.Second)
	for {
		select {
		case v := <-c.Subscribe():
			if fds, ok := v.([]FDEntry); ok {
				if len(fds) == 0 {
					t.Fatal("self should have open FDs")
				}
				t.Logf("fds: %d entries (first type=%q desc=%q)", len(fds), fds[0].Type, fds[0].Desc)
				return
			}
		case <-deadline:
			t.Fatal("no []FDEntry snapshot within 3s")
		}
	}
}
