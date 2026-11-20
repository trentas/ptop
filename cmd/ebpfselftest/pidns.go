//go:build linux && ebpf

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/trentas/ptop/internal/bpf"
	"github.com/trentas/ptop/pkg/collector"
)

// ─── pidns: a target in a child pid namespace, named from outside it (#197) ──
//
// --pid is the number ptop's own /proc shows. A container's process seen from
// the host — or from a `pid: host` container, the way a profiler deployed next
// to the services runs ptop — has that number out here and another one (1, 7,
// …) in its own namespace, and bpf_get_ns_current_pid_tgid() answers only in
// the task's own namespace. The filter compared the inner answer with the outer number,
// matched nothing, and every probe reported `active` and read zero. Every
// other case targets this process, which shares ptop's namespace, so none of
// them could see it.
//
// The child is this binary re-executed as pid 1 of a fresh pid namespace
// (CLONE_NEWPID). The parent names it by its OUTER pid, as ptop would, and on
// a go signal the child plants three answers:
//
//   - pidnsCalls getppid calls, exact: the filter itself;
//   - a CPU burn timed by its own thread clock: the axis #197 was found on;
//   - pidnsSleep naps in a loop until told to stop: the threads collector,
//     whose tids have to cross from the target's namespace to ptop's.

// pidnsCalls is how many getppid calls the child plants. Nothing else in the
// child calls getppid, so the count is exact.
const pidnsCalls = 2000

// pidnsBurn is the CPU the child burns, by its own thread clock.
const pidnsBurn = 300 * time.Millisecond

// pidnsSleep is one nap of the child's sleep loop: each is a switch out, so a
// one-second window holds up to 1s/pidnsSleep of them.
const pidnsSleep = 5 * time.Millisecond

func checkPidNS(g *grader, _ int) {
	const axis = "pidns"

	child := peerCmd("pidns")
	child.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWPID}
	stdin, err := child.StdinPipe()
	if err != nil {
		g.broken(axis, "the child's stdin", err)
		return
	}
	stdout, err := child.StdoutPipe()
	if err != nil {
		g.broken(axis, "the child's stdout", err)
		return
	}
	if err := child.Start(); err != nil {
		g.broken(axis, "start the child in a new pid namespace", err)
		return
	}
	// Closing stdin ends the child's sleep loop; the kill is for a child that
	// never got that far.
	defer func() { _ = stdin.Close(); _ = child.Process.Kill(); _ = child.Wait() }()
	lines := lineReader(stdout)

	if line, err := lines(5 * time.Second); err != nil || line != "ready" {
		g.broken(axis, "the child's start", fmt.Errorf("got %q: %v", line, err))
		return
	}
	outer := child.Process.Pid
	chain := bpf.NSpidChain(fmt.Sprintf("/proc/%d/status", outer))
	g.note(axis, "the child is pid %d here; NSpid %v", outer, chain)
	if len(chain) != 2 || chain[1] != 1 {
		g.broken(axis, "the child is pid 1 of a namespace below this one",
			fmt.Errorf("NSpid = %v, want [%d 1]", chain, outer))
		return
	}

	sysT, err := bpf.OpenSyscallTracer(bpf.TargetPID(outer))
	if err != nil {
		g.broken(axis, "pid filter, syscalls", fmt.Errorf("OpenSyscallTracer(%d): %w", outer, err))
		return
	}
	defer sysT.Close()
	cpuT, err := bpf.OpenCPUTracer(bpf.TargetPID(outer))
	if err != nil {
		g.broken(axis, "pid filter, cpu", fmt.Errorf("OpenCPUTracer(%d): %w", outer, err))
		return
	}
	defer cpuT.Close()
	thr := collector.NewThreadsEBPFCollector()
	if err := thr.Start(outer); err != nil {
		g.broken(axis, "threads collector", fmt.Errorf("Start(%d): %w", outer, err))
		return
	}
	defer thr.Stop()

	if _, err := fmt.Fprintln(stdin, "go"); err != nil {
		g.broken(axis, "signal the child", err)
		return
	}
	line, err := lines(10 * time.Second)
	burned, perr := strconv.ParseInt(strings.TrimPrefix(line, "burned "), 10, 64)
	if err != nil || !strings.HasPrefix(line, "burned ") || perr != nil {
		g.broken(axis, "the child's planted work", fmt.Errorf("got %q: %v", line, errors.Join(err, perr)))
		return
	}

	stats, err := sysT.Stats()
	if err != nil {
		g.broken(axis, "pid filter, syscalls", err)
		return
	}
	got := stats[unix.SYS_GETPPID].Count
	g.check(axis, "the pid filter counts the child's getppid calls, named by its outer pid",
		got == pidnsCalls, strconv.Itoa(pidnsCalls), strconv.FormatUint(got, 10))

	// On-CPU covers the burn and then some (the child's runtime threads, its
	// getppid calls). The lower bound leaves a fifth for a slice that began
	// before its thread was known.
	onCPU, err := cpuT.OnCPUNanos()
	if err != nil {
		g.broken(axis, "pid filter, cpu", err)
		return
	}
	floor := time.Duration(burned) * 8 / 10
	g.check(axis, "on-CPU covers the child's planted burn",
		time.Duration(onCPU) >= floor, ">= "+floor.String(), time.Duration(onCPU).String())

	// The threads collector: its tids are the ones this /proc shows, and the
	// kernel's switches have to reach them across the namespaces.
	planted := int(time.Second / pidnsSleep)
	best, tids, err := childSwitches(thr, outer, 4*time.Second)
	if err != nil {
		g.broken(axis, "threads collector", err)
		return
	}
	g.note(axis, "the threads collector published tids %v for the child", tids)
	g.check(axis, "the threads collector counts a sleeping thread's switches in a window",
		best >= uint64(planted/2), fmt.Sprintf(">= %d (half of %d naps a second)", planted/2, planted),
		strconv.FormatUint(best, 10))
}

// childSwitches reads the threads collector for up to d and returns the most
// switches any one of the target's threads had in a window, with the tids the
// collector published. A tid that is not in /proc/<pid>/task — a number from
// the target's own namespace leaking out — is an error.
func childSwitches(c *collector.ThreadsEBPFCollector, pid int, d time.Duration) (uint64, []int, error) {
	deadline := time.After(d)
	var best uint64
	var tids []int
	ch := c.Subscribe()
	for {
		select {
		case <-deadline:
			if tids == nil {
				return 0, nil, errors.New("no thread list published")
			}
			return best, tids, nil
		case v := <-ch:
			ts, ok := v.([]collector.ThreadInfo)
			if !ok {
				continue
			}
			tids = tids[:0]
			for _, t := range ts {
				if _, err := os.Stat(fmt.Sprintf("/proc/%d/task/%d", pid, t.TID)); err != nil {
					return 0, nil, fmt.Errorf("published tid %d is not one of /proc/%d/task", t.TID, pid)
				}
				tids = append(tids, t.TID)
				best = max(best, t.CtxSwitches)
			}
		}
	}
}

// lineReader returns a function that reads one line from r, giving up after
// the timeout it is called with: a child that hangs fails the case instead of
// the suite.
func lineReader(r io.Reader) func(time.Duration) (string, error) {
	lines := make(chan string)
	errs := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			lines <- sc.Text()
		}
		errs <- errors.Join(io.EOF, sc.Err())
	}()
	return func(timeout time.Duration) (string, error) {
		select {
		case l := <-lines:
			return l, nil
		case err := <-errs:
			return "", err
		case <-time.After(timeout):
			return "", fmt.Errorf("no line in %s", timeout)
		}
	}
}

// runPidNSChild is the child side: pid 1 of its own namespace.
func runPidNSChild() {
	// One thread does all the planting, so its slices are the ones graded.
	runtime.LockOSThread()
	in := bufio.NewScanner(os.Stdin)
	fmt.Println("ready")
	if !in.Scan() || in.Text() != "go" {
		os.Exit(1)
	}
	// A nap first: the thread was asleep when the tracers attached, and the
	// CPU program charges a slice only once it has seen the thread switch out.
	time.Sleep(10 * time.Millisecond)

	for i := 0; i < pidnsCalls; i++ {
		_ = unix.Getppid()
	}

	start := threadCPU()
	for threadCPU()-start < pidnsBurn {
	}
	burned := threadCPU() - start
	// Switch out, so the burn's slice is closed and charged before the parent
	// reads the counter.
	time.Sleep(10 * time.Millisecond)
	fmt.Printf("burned %d\n", burned.Nanoseconds())

	// Nap until stdin closes.
	done := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, os.Stdin); close(done) }()
	for {
		select {
		case <-done:
			os.Exit(0)
		default:
			time.Sleep(pidnsSleep)
		}
	}
}

// threadCPU is the calling thread's CPU time.
func threadCPU() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &ts); err != nil {
		return 0
	}
	return time.Duration(ts.Nano())
}
