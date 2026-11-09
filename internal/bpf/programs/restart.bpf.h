/* SPDX-License-Identifier: GPL-2.0 */
/*
 * restart.bpf.h — a syscall the kernel re-runs after a signal is ONE call
 * (#160), for the probes that count at the syscall exit (io, syscalls).
 *
 * A signal that lands on a blocking call stops it with one of the restart
 * codes below, and the exit tracepoint fires with that code before the kernel
 * decides what the program gets:
 *
 *   - re-run: no handler, or a handler with SA_RESTART (every Go handler), or
 *     -ERESTARTNOINTR. The kernel rewinds to the syscall instruction and the
 *     same call enters again with the same arguments, once the handler (if
 *     any) has returned through rt_sigreturn. The program made ONE call.
 *   - EINTR: a handler without SA_RESTART for -ERESTARTSYS, or any handler for
 *     -ERESTARTNOHAND. The call is over and returned EINTR at that exit.
 *
 * So at a restart code the probe stops the clock but neither counts nor
 * forgets the call. Two later events settle it:
 *
 *   - the same call enters again with the same first argument: the re-run.
 *     It keeps the first entry's start time, and its exit counts it once.
 *   - rt_sigreturn exits with -EINTR: the handler is returning EINTR to the
 *     interrupted call, so it ended at the exit already seen. rt_sigreturn
 *     returns the register it restores, which is -EINTR in that case and the
 *     re-run's first argument (arm64) or syscall number (x86) otherwise.
 *
 * Anything else in between (the handler's own syscalls, a write to a
 * self-pipe) leaves the pending call alone. A call never settled (the thread
 * killed in it, or a handler that leaves by siglongjmp) is never counted, and
 * the LRU maps that hold it evict it.
 *
 * -ERESTART_RESTARTBLOCK is not here: without a handler the kernel continues
 * it as restart_syscall, another syscall number, so its exit is counted as the
 * call's end, as before. Sleeps and timed waits use it; read and write do not.
 */
#ifndef PTOP_RESTART_BPF_H
#define PTOP_RESTART_BPF_H

#define PTOP_EINTR          4
#define PTOP_ERESTARTSYS    512
#define PTOP_ERESTARTNOINTR 513
#define PTOP_ERESTARTNOHAND 514

static __always_inline int ret_restarts(long ret)
{
    return ret == -PTOP_ERESTARTSYS || ret == -PTOP_ERESTARTNOINTR ||
           ret == -PTOP_ERESTARTNOHAND;
}

#endif /* PTOP_RESTART_BPF_H */
