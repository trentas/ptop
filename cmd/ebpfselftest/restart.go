//go:build linux && ebpf

package main

import (
	"fmt"
	"os"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/trentas/ptop/internal/bpf"
	"github.com/trentas/ptop/pkg/collector"
)

// ─── restart: a call the kernel re-runs after a signal is one call (#160) ──
//
// A signal that lands on a blocking read stops it with -ERESTARTSYS, and the
// syscall tracepoints see that exit. What happens next depends on the handler:
//
//   - SA_RESTART (Go installs every handler with it): the kernel re-runs the
//     read once the handler returns. The program made ONE read.
//   - no SA_RESTART: the read returns EINTR, and a program that wants the data
//     issues it again. Those are TWO reads.
//
// Both look the same at the first exit. The case plants both on one pipe, in
// alternate waits, and grades the count against the reads the program made.
// Before #160 the io and syscalls axes counted every exit, so each restarted
// read counted twice, its wait split in two.

const (
	saRestart       = 0x10000000 // SA_RESTART, the same on amd64 and arm64
	restartCycles   = 20
	restartPeriod   = 10 * time.Millisecond
	restartSignalAt = 3 * time.Millisecond // into each wait: the halves land in different buckets
)

// withoutRestart clears SA_RESTART from sig's action while f runs, so the
// signal makes an interrupted read return EINTR. The action stays Go's
// handler, which ignores a SIGUSR1 nobody asked to be notified of.
func withoutRestart(sig unix.Signal, f func()) error {
	// The kernel's struct sigaction: handler, flags, restorer, mask. Read and
	// written back whole, with only the flags changed.
	var act [4]uint64
	p := uintptr(unsafe.Pointer(&act))
	if _, _, e := unix.RawSyscall6(unix.SYS_RT_SIGACTION, uintptr(sig), 0, p, 8, 0, 0); e != 0 {
		return fmt.Errorf("read the %v action: %w", sig, e)
	}
	orig := act
	act[1] &^= saRestart
	if _, _, e := unix.RawSyscall6(unix.SYS_RT_SIGACTION, uintptr(sig), p, 0, 8, 0, 0); e != 0 {
		return fmt.Errorf("clear SA_RESTART on %v: %w", sig, e)
	}
	defer unix.RawSyscall6(unix.SYS_RT_SIGACTION, uintptr(sig), uintptr(unsafe.Pointer(&orig)), 0, 8, 0, 0)
	f()
	return nil
}

// interrupted is what the reader saw: every call it made, how many of them
// returned EINTR, and the time it spent inside them, by its own clock.
type interrupted struct {
	calls, eintr int
	wait         time.Duration
	pipe         string // the read end as /proc/<pid>/fd links it
}

// plantInterrupted runs restartCycles waits on a fresh pipe. A writer thread
// writes one byte every restartPeriod and signals the reader restartSignalAt
// into each wait: SIGURG on even cycles (restarted by the kernel), SIGUSR1 on
// odd ones (EINTR, re-issued by the reader). read is the call under test.
func plantInterrupted(read func(fd int, b []byte) (int, error)) (interrupted, error) {
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC); err != nil {
		return interrupted{}, err
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	var st unix.Stat_t
	if err := unix.Fstat(fds[0], &st); err != nil {
		return interrupted{}, err
	}

	got := interrupted{pipe: fmt.Sprintf("pipe:[%d]", st.Ino)}
	var wg sync.WaitGroup
	readerTID := make(chan int, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		quietThread(func() {
			var both unix.Sigset_t
			for _, s := range []unix.Signal{unix.SIGURG, unix.SIGUSR1} {
				both.Val[(s-1)/64] |= 1 << ((s - 1) % 64)
			}
			_ = unix.PthreadSigmask(unix.SIG_UNBLOCK, &both, nil)
			readerTID <- unix.Gettid()
			buf := make([]byte, 1)
			for n := 0; n < restartCycles; {
				t := time.Now()
				k, err := read(fds[0], buf)
				got.wait += time.Since(t)
				got.calls++
				if err == unix.EINTR {
					got.eintr++
					continue
				}
				if k > 0 {
					n++
				}
			}
		})
	}()
	tid := <-readerTID
	pid := os.Getpid()

	start, err := bpf.MonotonicNanos()
	if err != nil {
		return got, err
	}
	// The reader is in its first read well before the first signal, and that
	// read waits one period like the others.
	start += uint64(time.Millisecond)
	quietThread(func() {
		for i := 0; i < restartCycles; i++ {
			c := start + uint64(i)*uint64(restartPeriod)
			sleepUntil(c + uint64(restartSignalAt))
			sig := unix.SIGURG
			if i%2 == 1 {
				sig = unix.SIGUSR1
			}
			_ = unix.Tgkill(pid, tid, sig)
			sleepUntil(c + uint64(restartPeriod))
			_, _ = unix.Write(fds[1], []byte{1})
		}
	})
	wg.Wait()
	return got, nil
}

func checkRestart(g *grader, pid int) {
	var planted interrupted
	var plantErr error
	run := func(c collector.Collector, read func(int, []byte) (int, error)) ([]any, error) {
		var vals []any
		err := withoutRestart(unix.SIGUSR1, func() {
			var cerr error
			vals, cerr = collect(c, pid, 700*time.Millisecond, func() {
				planted, plantErr = plantInterrupted(read)
			})
			if cerr != nil {
				plantErr = cerr
			}
		})
		if err != nil {
			return nil, err
		}
		return vals, plantErr
	}

	// io: read(2), graded on the pipe's row and the latency histogram.
	vals, err := run(collector.NewIOEBPFCollector(), unix.Read)
	if err != nil {
		g.broken("restart", "plant interrupted reads under the io collector", err)
		return
	}
	g.note("restart", "io: %d reads made for %d bytes, %d returned EINTR", planted.calls, restartCycles, planted.eintr)
	if planted.eintr == 0 || planted.calls-planted.eintr != restartCycles {
		g.broken("restart", "the planted signals", fmt.Errorf("%d EINTR in %d calls: a signal did not land mid-read", planted.eintr, planted.calls))
		return
	}
	row := ioPipeRow(vals, planted.pipe)
	g.check("restart", "io: each read the program made counts once (#160)", row.Reads == uint64(planted.calls),
		fmt.Sprintf("%d (%d restarted by the kernel count once, %d EINTR count apart)", planted.calls, restartCycles-planted.eintr, planted.eintr),
		fmt.Sprint(row.Reads))
	// A restarted read split in two adds a call and no time, so the mean
	// drops. The row is the pipe's, both ends (one inode), so its mean is over
	// the writer's calls too; each takes microseconds, inside the tolerance.
	// The program's clock brackets each read from outside, a few microseconds
	// long per call.
	calls := planted.calls + restartCycles
	mean := planted.wait / time.Duration(calls)
	got := time.Duration(row.LatencyMs * float64(time.Millisecond))
	g.check("restart", fmt.Sprintf("io: the pipe's mean latency over its %d reads and %d writes is the program's own", planted.calls, restartCycles),
		closeTo(got, mean), fmt.Sprintf("%v ±5%%", mean.Round(10*time.Microsecond)), got.Round(10*time.Microsecond).String())

	// syscalls: readv(2), which nothing else in this process makes.
	vals, err = run(collector.NewSyscallsEBPFCollector(), func(fd int, b []byte) (int, error) {
		return unix.Readv(fd, [][]byte{b})
	})
	if err != nil {
		g.broken("restart", "plant interrupted readv under the syscalls collector", err)
		return
	}
	g.note("restart", "syscalls: %d readv made, %d returned EINTR", planted.calls, planted.eintr)
	var sc collector.SyscallEvent
	for _, v := range vals {
		if s, ok := v.([]collector.SyscallEvent); ok {
			for _, r := range s {
				if r.Name == "readv" {
					sc = r
				}
			}
		}
	}
	g.check("restart", "syscalls: each readv the program made counts once (#160)", sc.Count == uint64(planted.calls),
		fmt.Sprint(planted.calls), fmt.Sprint(sc.Count))
	lat := time.Duration(sc.LatencyNs)
	g.check("restart", "syscalls: readv latency summed is the program's own", closeTo(lat, planted.wait),
		fmt.Sprintf("%v ±5%%", round(planted.wait)), round(lat).String())
}

// ioPipeRow is the io collector's last row for one pipe: rows are cumulative.
func ioPipeRow(vals []any, pipe string) collector.IOFileStats {
	var row collector.IOFileStats
	for _, v := range vals {
		if s, ok := v.(collector.IOEBPFSnapshot); ok {
			for _, f := range s.TopFiles {
				if f.Path == pipe {
					row = f
				}
			}
		}
	}
	return row
}

// closeTo reports whether got is within 5% of want.
func closeTo(got, want time.Duration) bool {
	d := got - want
	if d < 0 {
		d = -d
	}
	return want > 0 && d <= want/20
}
