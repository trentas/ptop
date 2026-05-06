//go:build !linux || !ebpf

package bpf

// Available is false in default builds (without -tags=ebpf) or on non-Linux
// OSes. When false, every Open*Tracer returns an error immediately.
const Available = false
