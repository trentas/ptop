//go:build !linux || !ebpf

package bpf

import "errors"

// ResolveCgroupSpec is unavailable here: cgroup targeting is an eBPF feature
// (the filter runs in the kernel), so it needs Linux and -tags=ebpf.
func ResolveCgroupSpec(string) (string, uint64, error) {
	return "", 0, errors.New("cgroup targeting requires Linux with eBPF support (build -tags=ebpf)")
}

// CgroupOfPID is unavailable for the same reason as ResolveCgroupSpec.
func CgroupOfPID(int) (string, error) {
	return "", errors.New("cgroup paths require Linux with eBPF support (build -tags=ebpf)")
}
