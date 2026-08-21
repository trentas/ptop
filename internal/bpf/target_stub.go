//go:build !linux || !ebpf

package bpf

import "errors"

// ResolveCgroupSpec is unavailable here: cgroup targeting is an eBPF feature
// (the filter runs in the kernel), so it needs Linux and -tags=ebpf.
func ResolveCgroupSpec(string) (string, uint64, error) {
	return "", 0, errors.New("cgroup targeting requires Linux with eBPF support (build -tags=ebpf)")
}
