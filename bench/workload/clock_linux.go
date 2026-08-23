//go:build linux

package main

import (
	"syscall"
	"unsafe"
)

// clockGettimeProcessCPU reads CLOCK_PROCESS_CPUTIME_ID — this process's total
// CPU time across all threads, at nanosecond resolution.
func clockGettimeProcessCPU(ts *syscall.Timespec) error {
	// 2 is CLOCK_PROCESS_CPUTIME_ID; it is not exported by the syscall package.
	const clockProcessCPUTimeID = 2
	_, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, clockProcessCPUTimeID, uintptr(unsafe.Pointer(ts)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}
