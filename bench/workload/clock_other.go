//go:build !linux

package main

import (
	"errors"
	"syscall"
)

// The benchmark only runs where eBPF does. Elsewhere this fails, and
// selfCPUSeconds reports 0 rather than a wrong number.
func clockGettimeProcessCPU(*syscall.Timespec) error {
	return errors.New("CLOCK_PROCESS_CPUTIME_ID is Linux-only")
}
