//go:build !linux || !ebpf

package bpf

// Available é false em builds default (sem -tags=ebpf) ou em OS não-Linux.
// Quando false, todos os Open*Tracer retornam erro imediatamente.
const Available = false
