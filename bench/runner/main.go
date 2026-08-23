// Command runner measures what ptop costs the process it observes.
//
// It exists because the number ptop shipped with — "overhead <0.5%" — was an
// assertion with no measurement, no workload and no methodology behind it. It
// was also the wrong SHAPE of claim: ptop's dominant cost is a uprobe that
// fires once per allocation, so its overhead is a function of the target's
// allocation rate, not a constant. A single percentage cannot be right for
// both an idle service and one allocating a million times a second.
//
// So this sweeps allocation rate against collector configuration and reports a
// table. Reading one cell of it as "the" overhead is exactly the mistake the
// old number encoded.
//
// # Method
//
//   - The metric is the TARGET'S CPU TIME, not wall time. A uprobe executes on
//     the thread that tripped it, so its cost lands in the target's own CPU
//     accounting; and unlike wall time, CPU time does not move when the
//     scheduler deschedules the target in favour of ptop. This is not a
//     refinement — measured by wall time on this two-core host, identical runs
//     of the same configuration varied by 65x and the table contained
//     impossibilities like "ptop made the target 80% faster".
//
//   - Fixed work, variable time. Each run does an identical number of
//     iterations; run-to-run variance is far lower than for "ops completed in
//     a fixed window".
//
//   - EVERY CONFIGURATION IS SIZED SEPARATELY, and the metric is CPU time PER
//     ITERATION. This took three tries to get right and the failures are worth
//     recording, because each produced a confident table that was wrong:
//
//     Sizing the work by a guess left the compute-only baseline finishing in
//     200 microseconds — every percentage derived from it was noise over
//     noise. Sizing it by a calibrated BASELINE put the instrumented arm into
//     the minutes, since the heap probe costs a large multiple of the
//     uninstrumented run; the sweep never finished. Sizing it by the
//     EXPENSIVE arm bounded the run but left the baseline at ~0.1s, where its
//     own repetitions disagreed by ±22% and the decomposition cell — the one
//     that says how much is NOT the heap probe — came out at -28.8%, i.e.
//     "attaching ptop made the target faster".
//
//     Giving each configuration its own iteration count fixes all three:
//     every arm runs long enough to be measured, no arm runs longer than it
//     needs to, and dividing by iterations makes them comparable.
//
//   - The MEDIAN of N repetitions is reported, not the mean. One descheduled
//     run moves a mean and does not move a median, and on a shared machine
//     there is always one. The spread is printed too, so a reader can see when
//     a cell should not be trusted.
//
//   - The baseline is re-measured for every allocation rate, interleaved with
//     the instrumented runs, so machine drift over the sweep hits both arms.
//
//   - The target confirms every probe is attached before timing starts (see
//     the --start-file handshake in the workload), so no run can measure a
//     half-attached ptop and report it as attached.
//
//   - ptop's own CPU time is read from /proc and reported separately. It is a
//     different question from "how much slower is the target", and conflating
//     the two is part of how a number like <0.5% survives unchallenged.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// config is one ptop configuration under test. Decomposing by subsystem is an
// acceptance criterion, not a nicety: "ptop costs N%" is unactionable, while
// "the heap probe costs N% and everything else costs M%" tells an operator
// what to turn off.
type config struct {
	name    string
	ptop    bool
	disable string // --disable value; "" means everything on
}

var configs = []config{
	{name: "no ptop", ptop: false},
	{name: "ptop, all probes", ptop: true},
	{name: "ptop, no heap probe", ptop: true, disable: "heap"},
	{name: "ptop, heap probe only", ptop: true,
		disable: "cpu,threads,memory,syscalls,io,network,futex,signals,lifecycle,security,fd"},
}

// sweepPoint is one row of the table: a workload shape. compute sets how much
// unobservable work sits between allocations, which is what varies the
// allocation RATE — the axis the heap probe's cost actually scales on. The
// control row allocates nothing at all, isolating what the other probes cost.
type sweepPoint struct {
	compute int
	allocs  int
}

func (p sweepPoint) control() bool { return p.allocs == 0 }

type workloadResult struct {
	Iterations   int     `json:"iterations"`
	AllocsPerIt  int     `json:"allocs_per_iteration"`
	ElapsedSec   float64 `json:"elapsed_sec"`
	CPUSec       float64 `json:"cpu_sec"`
	OpsPerSec    float64 `json:"ops_per_sec"`
	AllocsPerSec float64 `json:"allocs_per_sec"`
	GoVersion    string  `json:"go_version"`
	GOMAXPROCS   int     `json:"gomaxprocs"`
}

type cell struct {
	nsPerIter    float64 // the metric: CPU nanoseconds per work iteration
	iterations   int
	medianCPU    float64
	medianWall   float64
	allocsPerSec float64
	ptopCPUSec   float64
	runs         []float64 // CPU ns/iteration, one per repetition
}

// spread is the relative gap between the fastest and slowest repetition. It is
// printed beside every overhead figure, because a cell whose own runs disagree
// by more than the effect being measured has not measured anything.
func (c cell) spread() float64 {
	if len(c.runs) == 0 || c.nsPerIter == 0 {
		return 0
	}
	lo, hi := c.runs[0], c.runs[0]
	for _, r := range c.runs {
		if r < lo {
			lo = r
		}
		if r > hi {
			hi = r
		}
	}
	return (hi - lo) / c.nsPerIter
}

func main() {
	workloadBin := flag.String("workload", "./workload", "path to the workload binary")
	ptopBin := flag.String("ptop", "./ptop", "path to the ptop binary (must be an eBPF build)")
	targetSec := flag.Float64("target-sec", 8, "calibrate the iteration count so the most expensive configuration takes at least this many CPU seconds")
	maxIterations := flag.Int("max-iterations", 200_000_000, "calibration ceiling, so a slow host cannot run away")
	repeats := flag.Int("repeats", 5, "runs per cell; the median is reported")
	warmup := flag.Duration("warmup", 3*time.Second, "workload warm-up before timing")
	computeSweepFlag := flag.String("compute-sweep", "64,640,6400,64000", "comma-separated compute-rounds values to sweep; more compute between allocations means a lower allocation rate")
	allocs := flag.Int("allocs", 1, "allocations per iteration at each sweep point")
	allocBytes := flag.Int("alloc-bytes", 128, "size of each allocation")
	skipControl := flag.Bool("no-control", false, "skip the allocation-free control row")
	flag.Parse()

	computes, err := parseInts(*computeSweepFlag)
	if err != nil {
		fatal("--compute-sweep: %v", err)
	}
	var sweep []sweepPoint
	if !*skipControl {
		// Allocation-free control: whatever overhead shows up here belongs to
		// the probes that are NOT per-allocation, measured with the expensive
		// one given nothing to fire on.
		sweep = append(sweep, sweepPoint{compute: computes[0], allocs: 0})
	}
	for _, c := range computes {
		sweep = append(sweep, sweepPoint{compute: c, allocs: *allocs})
	}
	for _, bin := range []string{*workloadBin, *ptopBin} {
		if _, err := os.Stat(bin); err != nil {
			fatal("%v", err)
		}
	}

	results := make(map[string]map[int]cell)
	for _, c := range configs {
		results[c.name] = make(map[int]cell)
	}

	// Allocation rate is the outer loop and configuration the inner one, so
	// every configuration at a given rate is measured close together in time.
	// Machine conditions drift over a sweep this long; interleaving means the
	// drift lands on the comparison's noise rather than on its result.
	for i, pt := range sweep {
		fmt.Fprintf(os.Stderr, "compute=%d allocs/iter=%d\n", pt.compute, pt.allocs)
		for _, c := range configs {
			fmt.Fprintf(os.Stderr, "  %-24s ", c.name)
			iters, err := calibrate(c, *workloadBin, *ptopBin, pt, *allocBytes, *warmup, *targetSec, *maxIterations)
			if err != nil {
				fatal("\ncalibrating %s at %+v: %v", c.name, pt, err)
			}
			cl, err := measure(c, *workloadBin, *ptopBin, iters, pt, *allocBytes, *repeats, *warmup)
			if err != nil {
				fatal("\n%v", err)
			}
			results[c.name][i] = cl
			fmt.Fprintf(os.Stderr, "%9d iters  %8.1f ns/iter (spread %.0f%%)  %.0fk allocs/s\n",
				iters, cl.nsPerIter, 100*cl.spread(), cl.allocsPerSec/1000)
		}
	}

	report(sweep, results, *repeats, *allocBytes)
}

// calibrate grows the iteration count until THIS configuration costs at least
// targetSec of CPU.
//
// Per-configuration sizing is the point: the arms differ by more than an order
// of magnitude, so any single iteration count either starves the cheap arm of
// resolution or makes the expensive one take minutes. Both happened; see the
// package comment.
//
// The ceiling stops a fast host from running away; a run that hits it is
// reported with whatever duration it reached rather than retried forever.
func calibrate(c config, workloadBin, ptopBin string, pt sweepPoint, allocBytes int, warmup time.Duration, targetSec float64, maxIterations int) (int, error) {
	iters := 50_000
	for round := 0; round < 12; round++ {
		res, _, err := runOnce(c, workloadBin, ptopBin, iters, pt, allocBytes, warmup)
		if err != nil {
			return 0, err
		}
		if res.CPUSec >= targetSec || iters >= maxIterations {
			return iters, nil
		}
		// Scale straight to the target with headroom rather than doubling: on
		// a fast host doubling from 50k takes a dozen rounds, each paying the
		// warm-up again. Capped per round so one anomalously fast measurement
		// cannot overshoot into a run that takes an hour.
		factor := targetSec / maxf(res.CPUSec, 1e-6)
		if factor > 20 {
			factor = 20
		}
		next := int(float64(iters) * factor * 1.15)
		if next <= iters {
			next = iters * 2
		}
		if next > maxIterations {
			next = maxIterations
		}
		iters = next
	}
	return iters, nil
}

// measure runs one cell `repeats` times and returns its median.
func measure(c config, workloadBin, ptopBin string, iterations int, pt sweepPoint, allocBytes, repeats int, warmup time.Duration) (cell, error) {
	var elapsed []float64
	var allocRate, ptopCPU float64

	var wall, perIter []float64
	for i := 0; i < repeats; i++ {
		res, cpu, err := runOnce(c, workloadBin, ptopBin, iterations, pt, allocBytes, warmup)
		if err != nil {
			return cell{}, err
		}
		elapsed = append(elapsed, res.CPUSec)
		wall = append(wall, res.ElapsedSec)
		perIter = append(perIter, res.CPUSec*1e9/float64(iterations))
		allocRate += res.AllocsPerSec / float64(repeats)
		ptopCPU += cpu / float64(repeats)
	}
	return cell{
		nsPerIter:    median(perIter),
		iterations:   iterations,
		medianCPU:    median(elapsed),
		medianWall:   median(wall),
		allocsPerSec: allocRate,
		ptopCPUSec:   ptopCPU,
		runs:         perIter,
	}, nil
}

// runOnce starts the workload, attaches ptop if the configuration calls for
// it, releases the workload's timed section, and collects both results.
func runOnce(c config, workloadBin, ptopBin string, iterations int, pt sweepPoint, allocBytes int, warmup time.Duration) (workloadResult, float64, error) {
	tmp, err := os.MkdirTemp("", "ptopbench")
	if err != nil {
		return workloadResult{}, 0, err
	}
	defer os.RemoveAll(tmp)
	startFile := filepath.Join(tmp, "go")

	var out, errBuf strings.Builder
	wl := exec.Command(workloadBin,
		"-iterations", strconv.Itoa(iterations),
		"-allocs", strconv.Itoa(pt.allocs),
		"-compute", strconv.Itoa(pt.compute),
		"-alloc-bytes", strconv.Itoa(allocBytes),
		"-warmup", warmup.String(),
		"-start-file", startFile,
	)
	wl.Stdout, wl.Stderr = &out, &errBuf
	if err := wl.Start(); err != nil {
		return workloadResult{}, 0, fmt.Errorf("start workload: %w", err)
	}
	defer func() {
		if wl.ProcessState == nil {
			_ = wl.Process.Kill()
			_, _ = wl.Process.Wait()
		}
	}()

	var ptop *exec.Cmd
	var ptopErr strings.Builder
	var cpuBefore float64
	if c.ptop && ptopBin != "" {
		sock := filepath.Join(tmp, "p.sock")
		args := []string{"--pid", strconv.Itoa(wl.Process.Pid), "--serve", "unix://" + sock}
		if c.disable != "" {
			args = append(args, "--disable", c.disable)
		}
		ptop = exec.Command(ptopBin, args...)
		ptop.Stderr = &ptopErr
		if err := ptop.Start(); err != nil {
			return workloadResult{}, 0, fmt.Errorf("start ptop: %w", err)
		}
		defer func() {
			_ = ptop.Process.Kill()
			_, _ = ptop.Process.Wait()
		}()

		// The socket appearing is ptop's own statement that every collector it
		// intends to start has started. Waiting for it, rather than sleeping,
		// is what makes "the probes were attached" a fact about this run.
		if err := waitForFile(sock, 30*time.Second); err != nil {
			return workloadResult{}, 0, fmt.Errorf("ptop never served (%v)\nptop stderr:\n%s", err, ptopErr.String())
		}
		cpuBefore = processCPUSeconds(ptop.Process.Pid)
	}

	if err := os.WriteFile(startFile, []byte("go"), 0o644); err != nil {
		return workloadResult{}, 0, err
	}
	if err := wl.Wait(); err != nil {
		return workloadResult{}, 0, fmt.Errorf("workload: %w\nstderr:\n%s", err, errBuf.String())
	}

	var cpu float64
	if ptop != nil {
		cpu = processCPUSeconds(ptop.Process.Pid) - cpuBefore
	}

	var res workloadResult
	if err := json.Unmarshal([]byte(out.String()), &res); err != nil {
		return workloadResult{}, 0, fmt.Errorf("decode workload output %q: %w", out.String(), err)
	}
	return res, cpu, nil
}

func waitForFile(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", path)
}

// processCPUSeconds reads utime+stime from /proc/<pid>/stat. Returns 0 when
// the process is gone, which the caller reads as "no CPU attributable".
func processCPUSeconds(pid int) float64 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	// The comm field can contain spaces and parentheses; everything after the
	// last ')' is positional.
	i := strings.LastIndexByte(string(data), ')')
	if i < 0 {
		return 0
	}
	fields := strings.Fields(string(data)[i+1:])
	// After comm and state, utime is field 11 and stime 12 in proc(5); with
	// state at index 0 here they land at 11 and 12.
	if len(fields) < 13 {
		return 0
	}
	utime, err1 := strconv.ParseFloat(fields[11], 64)
	stime, err2 := strconv.ParseFloat(fields[12], 64)
	if err1 != nil || err2 != nil {
		return 0
	}
	return (utime + stime) / clockTicks
}

// clockTicks is USER_HZ, 100 on every Linux port ptop supports.
const clockTicks = 100.0

func report(sweep []sweepPoint, results map[string]map[int]cell, repeats, allocBytes int) {
	base := configs[0].name

	fmt.Printf("# ptop overhead\n\n")
	fmt.Printf("Metric: the TARGET's CPU time per unit of work (user+system, nanoseconds\n")
	fmt.Printf("per iteration), median of %d runs, %d-byte allocations. Overhead is the\n", repeats, allocBytes)
	fmt.Printf("increase against the identical workload with no ptop attached.\n\n")
	fmt.Printf("`spread` is (slowest - fastest) / median across the repetitions of that\n")
	fmt.Printf("cell. Where spread is comparable to the overhead, the cell is noise and\n")
	fmt.Printf("should be read as such.\n\n")

	header := func() {
		fmt.Printf("| target allocation rate | ")
		for _, c := range configs[1:] {
			fmt.Printf("%s | ", c.name)
		}
		fmt.Printf("\n|---|")
		for range configs[1:] {
			fmt.Printf("---|")
		}
		fmt.Println()
	}

	header()
	for i, pt := range sweep {
		b := results[base][i]
		fmt.Printf("| %s | ", rateLabel(pt, b))
		for _, c := range configs[1:] {
			cl := results[c.name][i]
			over := 100 * (cl.nsPerIter - b.nsPerIter) / b.nsPerIter
			fmt.Printf("%+.1f%% <sub>±%.0f%%</sub> | ", over, 100*maxf(cl.spread(), b.spread()))
		}
		fmt.Println()
	}

	// Dividing the overhead by the allocation count exposes something the
	// percentages hide, and it is not the constant one would expect.
	fmt.Printf("\n## Cost per allocation observed\n\n")
	fmt.Printf("The percentages above are this cost divided by how much other work the\n")
	fmt.Printf("target does between allocations. It would be convenient if it were a\n")
	fmt.Printf("constant of the probe that could simply be multiplied by anyone's\n")
	fmt.Printf("allocation rate. It is not: it RISES as allocations get sparser.\n\n")
	fmt.Printf("The likely reason is cache and branch state. At a high allocation rate\n")
	fmt.Printf("the trap path, the BPF program and its maps stay hot, and each firing\n")
	fmt.Printf("reuses them; at a low one every firing is a cold path through the same\n")
	fmt.Printf("code. That is a hypothesis this harness does not test — it is stated so\n")
	fmt.Printf("the numbers are not mistaken for a linear model.\n\n")
	fmt.Printf("| target allocation rate | ")
	for _, c := range configs[1:] {
		fmt.Printf("%s | ", c.name)
	}
	fmt.Printf("\n|---|")
	for range configs[1:] {
		fmt.Printf("---|")
	}
	fmt.Println()
	for i, pt := range sweep {
		if pt.control() {
			continue // nothing allocated, so there is nothing to divide by
		}
		b := results[base][i]
		fmt.Printf("| %s | ", rateLabel(pt, b))
		for _, c := range configs[1:] {
			cl := results[c.name][i]
			perAlloc := (cl.nsPerIter - b.nsPerIter) / float64(pt.allocs)
			fmt.Printf("%+.0f ns | ", perAlloc)
		}
		fmt.Println()
	}

	if floor, ok := noiseFloor(sweep, results); ok {
		fmt.Printf("\nThe control row allocates nothing, so the per-allocation probe has\n")
		fmt.Printf("nothing to fire on and every cell in it SHOULD read 0%%. What it reads\n")
		fmt.Printf("instead is this host's floor: **±%.1f%%**. Attaching a probe cannot make a\n", floor)
		fmt.Printf("process faster, so a negative or small positive figure there is the\n")
		fmt.Printf("measurement apparatus, not the probe — and no overhead below that\n")
		fmt.Printf("magnitude is resolved by this run.\n")
	}

	fmt.Printf("\n## ptop's own CPU, as a share of one core\n\n")
	fmt.Printf("A separate question from the one above: this is what ptop costs the MACHINE,\n")
	fmt.Printf("not what it costs the observed process.\n\n")
	header()
	for i, pt := range sweep {
		b := results[base][i]
		fmt.Printf("| %s | ", rateLabel(pt, b))
		for _, c := range configs[1:] {
			cl := results[c.name][i]
			pct := 0.0
			if cl.medianWall > 0 {
				pct = 100 * cl.ptopCPUSec / cl.medianWall
			}
			fmt.Printf("%.0f%% | ", pct)
		}
		fmt.Println()
	}

	fmt.Printf("\n## Raw\n\n```\n")
	for i, pt := range sweep {
		fmt.Printf("compute=%d allocs/iter=%d\n", pt.compute, pt.allocs)
		for _, c := range configs {
			cl := results[c.name][i]
			fmt.Printf("  %-24s %9d iters  %9.1f ns/iter  cpu_median=%.3fs  ns/iter runs=%s\n",
				c.name, cl.iterations, cl.nsPerIter, cl.medianCPU, fmtFloats(cl.runs))
		}
	}
	fmt.Printf("```\n")
}

// noiseFloor is the largest apparent overhead in the allocation-free control
// row. Nothing there should differ from the baseline at all — the expensive
// probe has nothing to fire on — so whatever the row reports is the host's
// run-to-run bias, and a smaller effect elsewhere in the table has not been
// measured.
//
// Publishing it beside the table is the difference between a benchmark and a
// number: without it, a reader cannot tell an overhead of 2% from a rounding
// artefact, and the first draft of this harness reported both.
func noiseFloor(sweep []sweepPoint, results map[string]map[int]cell) (float64, bool) {
	base := configs[0].name
	var worst float64
	var found bool
	for i, pt := range sweep {
		if !pt.control() {
			continue
		}
		b := results[base][i]
		if b.nsPerIter == 0 {
			continue
		}
		found = true
		for _, c := range configs[1:] {
			cl := results[c.name][i]
			d := math.Abs(100 * (cl.nsPerIter - b.nsPerIter) / b.nsPerIter)
			if d > worst {
				worst = d
			}
		}
		// The cells' own repetition spread is part of the same floor.
		if sp := 100 * b.spread(); sp > worst {
			worst = sp
		}
	}
	return worst, found
}

// rateLabel names a sweep row by the allocation rate actually achieved, not by
// the knob setting: "4 allocations per iteration" means nothing to a reader,
// while "2.3M allocations/sec" is the axis the cost actually scales on.
func rateLabel(pt sweepPoint, baseline cell) string {
	if pt.control() {
		return "0 (no allocations)"
	}
	r := baseline.allocsPerSec
	switch {
	case r >= 1e6:
		return fmt.Sprintf("%.1fM/s", r/1e6)
	case r >= 1e3:
		return fmt.Sprintf("%.0fk/s", r/1e3)
	default:
		return fmt.Sprintf("%.0f/s", r)
	}
}

func maxf(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

func fmtFloats(xs []float64) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = fmt.Sprintf("%.4f", x)
	}
	return "[" + strings.Join(parts, " ") + "]"
}

func parseInts(spec string) ([]int, error) {
	var out []int
	for _, raw := range strings.Split(spec, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("bad value %q", raw)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no values")
	}
	return out, nil
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "bench: "+format+"\n", args...)
	os.Exit(1)
}
