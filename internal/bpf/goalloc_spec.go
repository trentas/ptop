package bpf

// GoAllocDefaultSampleBytes is the default distance, in bytes allocated,
// between recorded allocation samples on the Go heap lane. 512KB is what Go's
// own heap profiler uses (runtime.MemProfileRate), for the same reason: a stack
// walk per allocation costs a large multiple of the allocation itself, and here
// that cost is charged to the TARGET's CPU accounting (#108).
//
// 0 records every allocation — exact per site, and on an allocation-heavy
// target a different program from the one being observed. See the sampling
// section of programs/goalloc.bpf.c.
//
// Declared here rather than in goalloc.go so it is available in every build:
// it is a command-line default, and the flag exists whether or not the binary
// was built with the eBPF lane.
const GoAllocDefaultSampleBytes uint64 = 512 * 1024
