//go:build linux && ebpf

package main

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/trentas/ptop/pkg/collector"
)

// checkFdClasses grades the split of read and write by the class of fd they hit
// (#176). On a thread of its own with signals blocked, it reads and writes a
// known number of times on one fd of each class. The Go runtime's own netpoller
// also reads and writes its eventfd, so "anon" is at least the planted count;
// every class is at least its own; and the classes must add up to the syscall's
// total exactly, because they split it.
func checkFdClasses(g *grader, pid int) {
	planted := map[string]int{"anon": 23, "pipe": 29, "socket": 31, "file": 37, "char": 41}

	dir, err := os.MkdirTemp("", "ptop-selftest-fdclass-")
	if err != nil {
		g.broken("fdclass", "a scratch directory", err)
		return
	}
	defer os.RemoveAll(dir)

	var setupErr error
	c := collector.NewSyscallsEBPFCollector()
	vals, err := collect(c, pid, 2500*time.Millisecond, func() {
		quietThread(func() {
			setupErr = plantFdClasses(dir, planted)
		})
	})
	if err != nil {
		g.broken("fdclass", "attach", err)
		return
	}
	if setupErr != nil {
		g.broken("fdclass", "plant the calls", setupErr)
		return
	}
	var last []collector.SyscallEvent
	for _, v := range vals {
		if s, ok := v.([]collector.SyscallEvent); ok {
			last = s
		}
	}
	for _, name := range []string{"read", "write"} {
		var ev *collector.SyscallEvent
		for i := range last {
			if last[i].Name == name {
				ev = &last[i]
			}
		}
		if !g.check("fdclass", name+" was published with a split by fd class", ev != nil && len(ev.FdClasses) > 0, "a split", fmt.Sprintf("%v", ev != nil)) {
			continue
		}
		got := map[string]uint64{}
		var sum, lat uint64
		for _, fc := range ev.FdClasses {
			got[fc.Class] = fc.Count
			sum += fc.Count
			lat += fc.LatencyNs
		}
		for _, cls := range []string{"anon", "pipe", "socket", "file", "char"} {
			want := uint64(planted[cls])
			g.check("fdclass", fmt.Sprintf("%s on a %s fd", name, cls), got[cls] >= want,
				fmt.Sprintf(">= %d (planted)", want), fmt.Sprint(got[cls]))
		}
		g.check("fdclass", name+": the classes add up to the total", sum == ev.Count,
			fmt.Sprint(ev.Count), fmt.Sprint(sum))
		g.check("fdclass", name+": the classes' latency adds up to the total", lat == ev.LatencyNs,
			fmt.Sprint(ev.LatencyNs), fmt.Sprint(lat))
	}
}

// plantFdClasses writes then reads n times on one fd of each class.
func plantFdClasses(dir string, n map[string]int) error {
	one := []byte{1}
	eight := make([]byte, 8)

	efd, err := unix.Eventfd(0, unix.EFD_CLOEXEC)
	if err != nil {
		return fmt.Errorf("eventfd: %w", err)
	}
	defer unix.Close(efd)
	for i := 0; i < n["anon"]; i++ {
		var v [8]byte
		v[0] = 1
		if _, err := unix.Write(efd, v[:]); err != nil {
			return err
		}
		if _, err := unix.Read(efd, eight); err != nil {
			return err
		}
	}

	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	defer unix.Close(p[0])
	defer unix.Close(p[1])
	for i := 0; i < n["pipe"]; i++ {
		if _, err := unix.Write(p[1], one); err != nil {
			return err
		}
		if _, err := unix.Read(p[0], one); err != nil {
			return err
		}
	}

	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("socketpair: %w", err)
	}
	defer unix.Close(sp[0])
	defer unix.Close(sp[1])
	for i := 0; i < n["socket"]; i++ {
		if _, err := unix.Write(sp[0], one); err != nil {
			return err
		}
		if _, err := unix.Read(sp[1], one); err != nil {
			return err
		}
	}

	ffd, err := unix.Open(dir+"/f", unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer unix.Close(ffd)
	for i := 0; i < n["file"]; i++ {
		if _, err := unix.Write(ffd, one); err != nil {
			return err
		}
		if _, err := unix.Seek(ffd, -1, 1); err != nil {
			return err
		}
		if _, err := unix.Read(ffd, one); err != nil {
			return err
		}
	}

	cfd, err := unix.Open("/dev/zero", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open /dev/zero: %w", err)
	}
	defer unix.Close(cfd)
	for i := 0; i < n["char"]; i++ {
		if _, err := unix.Write(cfd, one); err != nil {
			return err
		}
		if _, err := unix.Read(cfd, one); err != nil {
			return err
		}
	}
	return nil
}
