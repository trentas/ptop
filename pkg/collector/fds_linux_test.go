//go:build linux

package collector

import (
	"os"
	"strings"
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

// TestFDCollectorClassifiesAndBaselines plants one fd of each kind in this
// process and reads them the way the collector reads a target.
func TestFDCollectorClassifiesAndBaselines(t *testing.T) {
	dir := t.TempDir()
	file, err := os.Create(dir + "/planted")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()
	socks, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(socks[0])
	defer syscall.Close(socks[1])
	epfd, err := syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(epfd)
	evfd, _, errno := syscall.Syscall(syscall.SYS_EVENTFD2, 0, syscall.O_CLOEXEC, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	defer syscall.Close(int(evfd))

	c := NewFDCollector()
	c.pid = os.Getpid()
	c.resolver.ForPID(c.pid)

	first, events, err := c.collect()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if fe, ok := e.(FDEvent); ok {
			t.Errorf("the first poll is the baseline and must emit no event, got %q", fe.Message)
		}
	}

	want := map[int]struct {
		typ      string
		posKnown bool
	}{
		int(file.Fd()):    {"file", true},
		int(devnull.Fd()): {"file", false}, // a char device: pos never moves
		int(pr.Fd()):      {"pipe", false},
		socks[0]:          {"socket", false},
		epfd:              {"epoll", false},
		int(evfd):         {"event", false},
	}
	byFD := func(entries []FDEntry) map[int]FDEntry {
		m := make(map[int]FDEntry, len(entries))
		for _, e := range entries {
			m[e.FD] = e
		}
		return m
	}
	got := byFD(first)
	for fd, w := range want {
		e, ok := got[fd]
		if !ok {
			t.Errorf("fd %d not listed", fd)
			continue
		}
		if e.Type != w.typ || e.PosKnown != w.posKnown || !e.Preexisting {
			t.Errorf("fd %d (%s) = type %q posKnown %v preexisting %v; want %q %v true",
				fd, e.Desc, e.Type, e.PosKnown, e.Preexisting, w.typ, w.posKnown)
		}
	}

	// Between two polls: the file's offset moves, a byte goes through the
	// pipe, and a new file opens.
	if _, err := file.Write(make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
	if _, err := pw.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	opened, err := os.Create(dir + "/opened-later")
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()

	second, events, err := c.collect()
	if err != nil {
		t.Fatal(err)
	}
	got = byFD(second)
	if e := got[int(file.Fd())]; !e.Active || e.Bytes != 4096 {
		t.Errorf("written file: active %v bytes %d, want true 4096", e.Active, e.Bytes)
	}
	if e := got[int(pr.Fd())]; e.Active || e.Bytes != 0 {
		t.Errorf("pipe: active %v bytes %d; with no offset neither is a reading", e.Active, e.Bytes)
	}
	if e := got[int(opened.Fd())]; e.Preexisting {
		t.Errorf("a file opened after the first poll is not preexisting")
	}
	sawOpen := false
	for _, e := range events {
		if fe, ok := e.(FDEvent); ok && strings.Contains(fe.Message, "opened-later") {
			sawOpen = true
		}
	}
	if !sawOpen {
		t.Errorf("no openat event for the file opened between polls: %v", events)
	}
}
