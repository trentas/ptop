// probecost reports what each loaded eBPF program costs the machine, from the
// kernel's own accounting rather than from a benchmark delta.
//
// ─── Why this exists beside bench/runner ────────────────────────────────────
//
// The runner measures a probe by the increase it causes in the TARGET's CPU
// time per unit of work. That is the right question for a probe that fires on
// something the target does — the allocator uprobe fires once per allocation
// and costs hundreds of percent, an effect no floor hides.
//
// It cannot answer for a probe that fires at a fixed rate whatever the target
// does. The CPU attribution sampler (#125) runs 99 times a second per CPU and
// costs about a hundredth of one percent of a core. The best noise floor this
// repository's benchmark has ever achieved is ±1.8%, and typical runs are worse
// — three attempts at measuring that sampler produced floors of ±13%, ±20% and
// ±35%, with several cells reading NEGATIVE overhead, which is the harness
// correctly reporting that it measured nothing. The instrument was wrong for
// the magnitude by more than two orders of magnitude; no amount of tuning,
// repeats or quieter hosts could have closed that gap.
//
// The kernel already counts the quantity itself. With run-time statistics
// enabled it accumulates run_time_ns and run_cnt per loaded program, so two
// snapshots and a subtraction give every probe's cost exactly, with no
// benchmark, no workload and no noise. That is #108's rule applied to the
// measurement rather than to the product: before inferring a quantity from a
// noisy delta, check whether something already counts it.
//
// ─── What the numbers do and do not include ─────────────────────────────────
//
//   - They count time spent INSIDE each BPF program. The interrupt, trap or
//     tracepoint machinery that reaches the program is not counted, nor is the
//     cache and branch-predictor disturbance the probe leaves behind for the
//     target. So a figure here is a floor on the true cost, not the whole of it.
//   - Enabling the statistics costs a timestamp pair per program run, which
//     the measurement then charges to the program. The numbers therefore
//     OVERSTATE slightly, which is the safe direction.
//   - Statistics are enabled through bpf(BPF_ENABLE_STATS), scoped to this
//     process's lifetime, so nothing is left switched on for the host when it
//     exits. That is deliberately not the global kernel.bpf_stats_enabled
//     sysctl, which stays on until someone remembers to clear it.
//
// Run it while the probes are attached — typically alongside a ptop the
// operator started separately, since it measures whatever the machine has
// loaded rather than starting anything itself. Needs the same privileges as
// loading a program.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/cilium/ebpf"
)

// statsRunTime is bpf(2)'s BPF_STATS_RUN_TIME. Spelled out here rather than
// imported: cilium/ebpf keeps the constant in an internal package.
const statsRunTime = 0

// progStat is one program's cumulative accounting at a point in time.
type progStat struct {
	name    string
	typ     string
	runtime time.Duration
	count   uint64
}

// delta is one program's cost over the measured window.
type delta struct {
	name    string
	typ     string
	runtime time.Duration
	count   uint64
}

func main() {
	window := flag.Duration("window", 30*time.Second, "how long to measure for")
	minRuns := flag.Uint64("min-runs", 1, "omit programs that ran fewer times than this in the window")
	flag.Parse()

	closer, err := ebpf.EnableStats(statsRunTime)
	if err != nil {
		fatal("enable BPF run-time statistics: %v\n(needs CAP_BPF/CAP_SYS_ADMIN, and a kernel with BPF_ENABLE_STATS)", err)
	}
	defer closer.Close()

	// Snapshot only after enabling: a program's counters are zero until stats
	// are on, so the first reading taken immediately would attribute the
	// enable-to-first-read interval to the window.
	before, err := snapshot()
	if err != nil {
		fatal("%v", err)
	}
	fmt.Fprintf(os.Stderr, "measuring %d loaded programs for %v...\n", len(before), *window)
	time.Sleep(*window)
	after, err := snapshot()
	if err != nil {
		fatal("%v", err)
	}

	report(os.Stdout, diff(before, after, *minRuns), *window)
}

// snapshot reads every loaded program's accounting, keyed by program id.
//
// Keyed by id and not by name: names are truncated to 15 characters by the
// kernel and several of ptop's programs collide there (two sched_switch
// handlers both arrive as "handle_sched_sw"), so folding on the name would
// silently merge two probes into one row.
func snapshot() (map[ebpf.ProgramID]progStat, error) {
	out := make(map[ebpf.ProgramID]progStat)
	var id ebpf.ProgramID
	for {
		next, err := ebpf.ProgramGetNextID(id)
		if err != nil {
			break // end of the list, or a program disappeared mid-walk
		}
		id = next
		p, err := ebpf.NewProgramFromID(id)
		if err != nil {
			continue // unloaded between the walk and the open; not an error
		}
		info, err := p.Info()
		p.Close()
		if err != nil {
			continue
		}
		rt, ok := info.Runtime()
		if !ok {
			return nil, fmt.Errorf("kernel reports no run-time statistics; is this kernel older than 5.1?")
		}
		rc, _ := info.RunCount()
		out[id] = progStat{name: info.Name, typ: info.Type.String(), runtime: rt, count: rc}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no BPF programs are loaded — start the probes first, this tool attaches nothing")
	}
	return out, nil
}

// diff subtracts two snapshots, keeping only programs present in both. A
// program loaded or unloaded mid-window has no comparable pair and is dropped
// rather than reported against a partial window.
func diff(before, after map[ebpf.ProgramID]progStat, minRuns uint64) []delta {
	out := make([]delta, 0, len(after))
	for id, a := range after {
		b, ok := before[id]
		if !ok || a.count < b.count {
			continue // new program, or the id was reused by another
		}
		runs := a.count - b.count
		if runs < minRuns {
			continue
		}
		out = append(out, delta{
			name: a.name, typ: a.typ,
			runtime: a.runtime - b.runtime, count: runs,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].runtime != out[j].runtime {
			return out[i].runtime > out[j].runtime
		}
		return out[i].name < out[j].name
	})
	return out
}

func report(w *os.File, rows []delta, window time.Duration) {
	fmt.Fprintf(w, "%-20s %-12s %10s %9s %13s\n", "program", "type", "runs/s", "ns/run", "% of a core")
	var total float64
	for _, r := range rows {
		pct := coreShare(r.runtime, window)
		total += pct
		fmt.Fprintf(w, "%-20s %-12s %10.0f %9.0f %12.3f%%\n",
			r.name, r.typ, float64(r.count)/window.Seconds(), float64(r.runtime)/float64(r.count), pct)
	}
	fmt.Fprintf(w, "%-44s %12.3f%%\n", "TOTAL", total)
}

// coreShare is the share of ONE core a program's run time represents. Not of
// the machine: a per-CPU probe's cost is easier to reason about against a
// single core, and dividing by the core count would make the same probe look
// cheaper on a bigger host while costing exactly the same.
func coreShare(runtime, window time.Duration) float64 {
	if window <= 0 {
		return 0
	}
	return float64(runtime) / float64(window) * 100
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
