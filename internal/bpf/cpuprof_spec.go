package bpf

import "fmt"

// Sampling-rate policy for the CPU attribution axis (#125), kept free of build
// tags so the flag parsing, the docs and the tests agree on one set of numbers
// on every platform — the same reason GoAllocDefaultSampleBytes lives apart
// from the loader that uses it.

const (
	// CPUProfDefaultHz is the per-CPU sampling rate, in Hz.
	//
	// 99 and not 100, deliberately. A sampler whose rate divides a workload's
	// period lands on the same phase of that workload's cycle every time, so
	// one function takes every sample and its neighbours take none — the
	// time-domain twin of the fixed-threshold aliasing goalloc.bpf.c draws a
	// random threshold to avoid (#108), and 10ms loops are everywhere. An odd
	// rate that divides no common period spreads the sample points across the
	// cycle instead.
	CPUProfDefaultHz = 99

	// CPUProfMaxHz caps what an operator can ask for. The sampler's cost is
	// paid by every CPU on the machine, target or not, so an unbounded rate is
	// a way to make ptop expensive by typo.
	CPUProfMaxHz = 1000

	// cpuProfLoudHz is where a rate stops being free and starts being a choice
	// worth naming out loud. Below it the probe sits in the tier the overhead
	// benchmark measures as indistinguishable from noise.
	cpuProfLoudHz = 250
)

// NormalizeCPUProfHz resolves a requested sampling rate to the one that will be
// used, and returns a warning when the two differ or when the rate is high
// enough that the operator should know what they asked for. An empty warning
// means there is nothing to say.
//
// 0 means "unset" and yields the default, so the zero value of a config struct
// is the cheap, safe rate rather than something a caller has to remember to
// fill in.
func NormalizeCPUProfHz(hz int) (int, string) {
	switch {
	case hz == 0:
		return CPUProfDefaultHz, ""
	case hz < 0:
		return CPUProfDefaultHz, fmt.Sprintf(
			"cpuprof: sampling rate %dHz is not a rate; using %dHz", hz, CPUProfDefaultHz)
	case hz > CPUProfMaxHz:
		return CPUProfMaxHz, fmt.Sprintf(
			"cpuprof: sampling rate %dHz exceeds the %dHz cap; using %dHz",
			hz, CPUProfMaxHz, CPUProfMaxHz)
	case hz >= cpuProfLoudHz:
		return hz, fmt.Sprintf(
			"cpuprof: sampling at %dHz per CPU — well above the %dHz default, and the cost "+
				"is paid on every CPU of the machine, not just the target's",
			hz, CPUProfDefaultHz)
	default:
		return hz, ""
	}
}
