package bpf

import "fmt"

// Sampling-rate policy for the CPU attribution axis (#125), kept free of build
// tags so the flag parsing, the docs and the tests agree on one set of numbers
// on every platform — the same reason GoAllocDefaultSampleBytes lives apart
// from the loader that uses it.

const (
	// CPUProfDefaultHz is the per-CPU sampling rate, in Hz.
	//
	// 99 and not 100, as cheap insurance against phase-locking on a periodic
	// workload: a sampler whose period divides the workload's would land at the
	// same point of every cycle, and one function would take every sample while
	// its neighbours took none — the time-domain shape of the fixed-threshold
	// aliasing goalloc.bpf.c draws a random threshold to avoid (#108).
	//
	// Stated as the reason for a choice, NOT as a defect measured here, because
	// the attempt to measure it failed: a workload alternating 8ms in one
	// function with 2ms in another, sampled at exactly 100Hz on a 7.0 kernel,
	// came out 80/77/79/85 against a true 80 — no lock at any phase. Two
	// reasons, either sufficient: perf freq mode re-derives its period from the
	// rate it observes (the very behaviour #108 found underdelivering), so the
	// phase dithers instead of locking; and a real workload's own timing jitter
	// does the same. The insurance stays because it costs nothing and because a
	// FIXED-period sampler — PerfBitFreq off, a period in nanoseconds — has no
	// such dithering and would lock.
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
