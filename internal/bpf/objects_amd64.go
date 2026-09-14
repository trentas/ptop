//go:build linux && ebpf && amd64

package bpf

// Compiled eBPF objects for amd64.
//
// They are selected by build tag rather than by a path the release swaps
// between builds, because goreleaser builds both architectures from one
// working tree in one run (#123). BPF bytecode is portable; the pt_regs
// offsets bpf_tracing.h bakes into it are not, so an object built for the
// wrong architecture loads, verifies, attaches — and reads every uprobe
// argument from the wrong register.
//
// Build them with `make gen GOARCH=amd64`, on a host of that architecture:
// the asm/ headers have to match __TARGET_ARCH_*, and that mismatch failing to
// compile is what keeps this honest.

import _ "embed"

//go:embed programs/obj/amd64/cpu.bpf.o
var cpuBPFObj []byte

//go:embed programs/obj/amd64/futex.bpf.o
var futexBPFObj []byte

//go:embed programs/obj/amd64/goalloc.bpf.o
var goallocBPFObj []byte

//go:embed programs/obj/amd64/heap.bpf.o
var heapBPFObj []byte

//go:embed programs/obj/amd64/io.bpf.o
var ioBPFObj []byte

//go:embed programs/obj/amd64/memory.bpf.o
var memoryBPFObj []byte

//go:embed programs/obj/amd64/network.bpf.o
var networkBPFObj []byte

//go:embed programs/obj/amd64/proc.bpf.o
var procBPFObj []byte

//go:embed programs/obj/amd64/security.bpf.o
var securityBPFObj []byte

//go:embed programs/obj/amd64/signal.bpf.o
var signalBPFObj []byte

//go:embed programs/obj/amd64/syscalls.bpf.o
var syscallsBPFObj []byte

//go:embed programs/obj/amd64/threads.bpf.o
var threadsBPFObj []byte

//go:embed programs/obj/amd64/tls.bpf.o
var tlsBPFObj []byte
