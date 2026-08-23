// Command workload is the benchmark target: a program whose allocation rate is
// a knob, so overhead can be measured as a FUNCTION of allocation rate rather
// than as a single number.
//
// That shape is the point. ptop's heap lane hangs a uprobe on every allocation
// — libc malloc/free, or runtime.mallocgc on Go — so its cost scales with how
// often the target allocates, not with wall time. A process that allocates
// twice as often pays twice as much. Any single "overhead is N%" figure is
// therefore a claim about one workload, and quoting it without the workload is
// what made the old number unfalsifiable.
//
// The work is deliberately mixed: a compute part that no probe can observe,
// and an allocation part that every probe does. Sweeping the ratio separates
// "ptop costs something" from "ptop costs something HERE".
//
// It measures fixed work in variable time, not the reverse: total time for a
// fixed op count has far less run-to-run variance than ops completed in a
// fixed window, and variance is the whole difficulty at these effect sizes.
//
// It reports CPU time as well as wall time, and the runner uses the CPU
// figure. That is not a refinement, it is what makes the measurement possible
// on a shared machine: wall time here varied 65x between identical runs,
// because the benchmark host has two cores and ptop is competing for them. A
// uprobe executes IN THE CONTEXT of the thread that tripped it, so its cost
// lands in the target's own CPU accounting — which is immune to the target
// being descheduled, and is precisely the quantity "how much does observing
// this process cost the process" is asking about.
//
// ptop's own CPU is a different question, reported separately by the runner.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"
)

type result struct {
	Iterations    int     `json:"iterations"`
	ComputeRounds int     `json:"compute_rounds"`
	AllocsPerIt   int     `json:"allocs_per_iteration"`
	AllocBytes    int     `json:"alloc_bytes"`
	ElapsedSec    float64 `json:"elapsed_sec"`
	CPUSec        float64 `json:"cpu_sec"`
	OpsPerSec     float64 `json:"ops_per_sec"`
	AllocsPerSec  float64 `json:"allocs_per_sec"`
	Checksum      uint64  `json:"checksum"`
	GoVersion     string  `json:"go_version"`
	GOMAXPROCS    int     `json:"gomaxprocs"`
}

func main() {
	iters := flag.Int("iterations", 2_000_000, "compute iterations to run")
	allocsPerIt := flag.Int("allocs", 1, "heap allocations per iteration (0 = compute only)")
	allocBytes := flag.Int("alloc-bytes", 128, "size of each allocation")
	computeRounds := flag.Int("compute", 64, "unobservable mixing steps per iteration — the knob that sets how much OTHER work sits between allocations, and therefore the allocation RATE at a given throughput")
	warmup := flag.Duration("warmup", 2*time.Second, "run un-timed for at least this long before the clock starts")
	startFile := flag.String("start-file", "", "if set, warm up until this file exists before timing (the orchestrator creates it once ptop has attached)")
	startTimeout := flag.Duration("start-timeout", 30*time.Second, "give up waiting for --start-file after this long")
	flag.Parse()

	fmt.Fprintf(os.Stderr, "workload pid %d\n", os.Getpid())

	// The warm-up exists so the measurement does not include process start,
	// the orchestrator attaching ptop, or the first GC cycles. Without it the
	// attached runs pay for setup the baseline runs never do, which inflates
	// the overhead by an amount that has nothing to do with the probe.
	//
	// --start-file makes that ordering a fact rather than a hope. A fixed
	// warm-up is a bet that ptop finishes attaching inside it; the file makes
	// the orchestrator say so. Every probe must be live before the first timed
	// iteration, or the run silently measures a partly-instrumented process
	// and reports it as instrumented.
	deadline := time.Now().Add(*warmup)
	giveUp := time.Now().Add(*startTimeout)
	for {
		run(50_000, *computeRounds, *allocsPerIt, *allocBytes)
		if time.Now().Before(deadline) {
			continue
		}
		if *startFile == "" {
			break
		}
		if _, err := os.Stat(*startFile); err == nil {
			break
		}
		if time.Now().After(giveUp) {
			fmt.Fprintf(os.Stderr, "workload: --start-file %s never appeared\n", *startFile)
			os.Exit(2)
		}
	}
	runtime.GC()

	cpuBefore := selfCPUSeconds()
	start := time.Now()
	sum := run(*iters, *computeRounds, *allocsPerIt, *allocBytes)
	elapsed := time.Since(start)
	cpu := selfCPUSeconds() - cpuBefore

	totalAllocs := float64(*iters) * float64(*allocsPerIt)
	res := result{
		Iterations:    *iters,
		ComputeRounds: *computeRounds,
		AllocsPerIt:   *allocsPerIt,
		AllocBytes:    *allocBytes,
		ElapsedSec:    elapsed.Seconds(),
		CPUSec:        cpu,
		OpsPerSec:     float64(*iters) / elapsed.Seconds(),
		AllocsPerSec:  totalAllocs / elapsed.Seconds(),
		Checksum:      sum,
		GoVersion:     runtime.Version(),
		GOMAXPROCS:    runtime.GOMAXPROCS(0),
	}
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(res); err != nil {
		os.Exit(1)
	}
}

// run does `iters` units of work, each with `rounds` mixing steps and
// `allocs` heap allocations of `size` bytes. The checksum is returned and
// printed so the compiler cannot eliminate any of it — a benchmark whose work
// is optimized away measures the probe against nothing.
//
//go:noinline
func run(iters, rounds, allocs, size int) uint64 {
	var sum uint64
	for i := 0; i < iters; i++ {
		// Compute: unobservable to any uprobe, so it dilutes the allocation
		// signal in a controlled way.
		x := uint64(i)
		for r := 0; r < rounds; r++ {
			x = x*2654435761 + 1
			x ^= x >> 13
		}
		sum += x

		for a := 0; a < allocs; a++ {
			b := make([]byte, size)
			b[0] = byte(x)
			b[size-1] = byte(a)
			sum += uint64(b[0]) + uint64(b[size-1])
		}
	}
	return sum
}

// selfCPUSeconds is this process's CPU time, the metric the runner compares.
// It counts time actually spent executing — including the uprobe bodies, which
// run on the tripping thread — and excludes time descheduled, which on a
// contended host is most of the variance.
//
// CLOCK_PROCESS_CPUTIME_ID rather than getrusage: getrusage is tick-accounted
// on kernels without precise CPU accounting, giving millisecond granularity.
// The runner sizes work so the cheapest configuration is short, so the clock
// has to resolve tens of milliseconds without quantising them into steps.
func selfCPUSeconds() float64 {
	var ts syscall.Timespec
	if err := clockGettimeProcessCPU(&ts); err != nil {
		return 0
	}
	return float64(ts.Sec) + float64(ts.Nsec)/1e9
}
