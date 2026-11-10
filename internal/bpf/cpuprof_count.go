package bpf

// CPUProfCount mirrors `struct cpuprof_count` in programs/cpuprof.bpf.c: one
// stack's samples in a window, and how many of them interrupted the CPU in
// kernel mode (#152). The kernel ones are inside Samples, attributed to the
// user frame that entered the kernel.
type CPUProfCount struct {
	Samples uint64
	Kernel  uint64
}
