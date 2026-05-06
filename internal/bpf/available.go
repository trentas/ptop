//go:build linux && ebpf

package bpf

// Available is true when the binary was compiled with `-tags=ebpf` on Linux.
// In any other build (default or non-Linux OS) it's false. main.go uses it
// to distinguish "eBPF tried and failed" from "binary built without eBPF".
const Available = true
