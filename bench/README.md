# Measuring what ptop costs

This directory answers a question ptop used to assert: **how much does
observing a process cost that process?**

The old answer was `overhead <0.5%`, printed in the TUI footer and the README.
Nothing produced it. There was no harness, no workload and no raw data in
either this repository or Witness's, so the figure could not be reproduced,
disputed, or updated when a probe was added.

It was also the wrong *shape* of answer. ptop's dominant cost is a uprobe on
the allocator — libc `malloc`/`free`, or `runtime.mallocgc` on a Go target —
which fires once per allocation. Its cost therefore scales with **how often the
target allocates**, not with wall time. No single percentage can be true for
both an idle service and one allocating a million times a second, so what this
produces is a table across allocation rates rather than a number.

## Two instruments, and which question each one answers

There are two harnesses here, because "what does a probe cost" is two questions
with two different right answers.

| | `make bench` (`runner/`) | `make probe-cost` (`probecost/`) |
|---|---|---|
| measures | the increase in the TARGET's CPU time per unit of work | the time the KERNEL spends in each BPF program |
| source | a benchmark delta against an un-instrumented baseline | the kernel's own `run_time_ns` / `run_cnt` per program |
| good for | probes that fire on something the target does | probes that fire at a fixed rate |
| floor | this host's noise, published with every run (±1.8% at best here) | none — it is a counter, not a difference |
| misses | nothing, but cannot resolve small effects | the trap/interrupt machinery around the program, and cache disturbance |

**Use the second one for anything that does not fire per event.** The CPU
attribution sampler (#125) runs 99 times a second per CPU and costs about a
hundredth of one percent of a core. The benchmark's best floor in this
repository is ±1.8% — more than two orders of magnitude too coarse — and three
attempts to measure that sampler with it produced floors of ±13%, ±20% and
±35%, several cells reading *negative* overhead, and no answer. That was not a
noisy machine; it was the wrong ruler. No number of repeats, no longer runs and
no quieter host would have closed a 160x gap.

It is worth naming the general shape, because this repository has met it before
(#108): **before inferring a quantity from a noisy delta, check whether
something already counts the thing itself.** Here the kernel does.

## Running it

eBPF needs privileges. Either run as root, or use a privileged container, which
is what the `bench` target does. Root, specifically — this benchmark is about
the heap uprobe, and a `setcap`'d binary needs `cap_sys_admin` before that
probe attaches at all (`ptop --caps` says so; see README → Permissions):

```
make bench
```

`make probe-cost` is the other one. It starts nothing — run it while ptop is
already attached, from any container on the host, since BPF programs are
global:

```
sudo ./bin/ptop --pid $PID --serve unix:///run/ptop.sock &
make probe-cost PROBECOST_ARGS="-window 30s"
```

Statistics are enabled through `bpf(BPF_ENABLE_STATS)`, scoped to the tool's
own lifetime, so nothing is left switched on for the host — deliberately not
the global `kernel.bpf_stats_enabled` sysctl, which stays on until someone
remembers to clear it. Enabling them costs a timestamp pair per program run,
charged to the program, so the figures overstate slightly: the safe direction.

The raw form, if you want to drive it yourself:

```
go build -o /tmp/b/workload ./bench/workload
go build -o /tmp/b/runner   ./bench/runner
go build -tags=ebpf -o /tmp/b/ptop ./cmd/ptop

sudo /tmp/b/runner -workload /tmp/b/workload -ptop /tmp/b/ptop
```

Useful flags: `-allocs` (the sweep, allocations per iteration), `-repeats`,
`-target-sec` (how long a calibrated baseline run should take).

## Method, and why each part is there

**The metric is the target's CPU time, not its wall time.** A uprobe executes
on the thread that tripped it, so its cost lands in the target's own
user+system time. Wall time also moves when the scheduler runs ptop instead of
the target, which is not the question being asked. This is not a refinement:
measured by wall time on a two-core host, identical runs of the same
configuration varied by 65x, and the resulting table contained impossibilities
such as *"ptop made the target 80% faster"*.

**Fixed work, variable time.** Every run does an identical number of
iterations and reports how long that took. Measuring the reverse — work
completed in a fixed window — has far higher run-to-run variance, and variance
is the entire difficulty at these effect sizes.

**The work is calibrated, not guessed.** Before each sweep point the runner
grows the iteration count until an uninstrumented run costs at least
`-target-sec` of CPU. A percentage computed against a baseline that finished in
200 microseconds is noise divided by noise — which is exactly what the first
draft of this harness reported before the calibration step existed.

**Median, with the spread shown.** One descheduled run moves a mean and does
not move a median, and on a shared machine there is always one. The spread
(slowest − fastest, over the median) is printed beside every cell: where it is
comparable to the overhead, the cell has not measured anything and says so.

**The baseline is re-measured at every allocation rate**, interleaved with the
instrumented runs, so drift in machine conditions over a long sweep lands on
both arms rather than on the result.

**Attachment is a handshake, not a sleep.** The workload warms up until the
runner creates a start file, and the runner creates it only after ptop's socket
appears — ptop's own statement that its collectors have started. Without that,
a run can measure a half-attached ptop and report it as attached.

**The workload mixes observable and unobservable work.** A compute part no
probe can see, and an allocation part every probe does. Sweeping the ratio is
what separates *"ptop costs something"* from *"ptop costs something here"*.

## Configurations

| Configuration | What it isolates |
|---|---|
| no ptop | the baseline |
| ptop, all probes | what an operator actually pays |
| ptop, no heap probe | everything except the allocator uprobe (`--disable heap`) |
| ptop, heap probe only | the allocator uprobe alone, sampled (the default) |
| ptop, heap probe unsampled | the same probe walking a stack on EVERY allocation (`--heap-sample-bytes 0`) |
| ptop, cpu sampler only | the CPU attribution sampler alone (#125) |

Read the last column differently from the heap ones. The heap probe fires once
per allocation, so its cost scales with the axis this table sweeps. The CPU
sampler fires at a fixed rate per CPU whatever the target does, so its cost per
unit of the target's CPU time should be roughly constant down the column — and
the control row, which allocates nothing, is where it is least contaminated by
anything else.

The decomposition is the actionable part. *"ptop costs N%"* leaves an operator
with nothing to do; *"the heap probe is N% of it and you can turn it off with
`--disable heap`"* is a decision they can make.

The last two rows are a pair, and the gap between them is why the Go allocation
lane samples (#108). The expensive half of that probe is the user stack walk,
not the counting, so the default takes one stack per 512KB allocated
(`--heap-sample-bytes`) instead of one per allocation. Keeping both columns
means the choice stays measured rather than argued: the unsampled column is
what every row of the first published table measured, so the two are directly
comparable.

It also stops the cost being invisible. A uprobe runs on the thread that
tripped it, so what it costs lands in the target's own CPU accounting — and
ptop's CPU axis samples the target on-CPU, so ptop then reports that cost AS
THE TARGET'S CPU. An unsampled heap probe did not merely tax the target; it
changed the number ptop published about it.

## Reading the result

Take the row whose allocation rate resembles your workload. Quoting a single
cell as "ptop's overhead" repeats the mistake this directory exists to correct.
