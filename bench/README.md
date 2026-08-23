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

## Running it

eBPF needs privileges. Either run as root on a host with `CAP_BPF`, or use a
privileged container, which is what the `bench` target does:

```
make bench
```

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
| ptop, no heap probe | everything except the per-allocation uprobe (`--disable heap`) |
| ptop, heap probe only | the per-allocation uprobe alone |

The decomposition is the actionable part. *"ptop costs N%"* leaves an operator
with nothing to do; *"the heap probe is N% of it and you can turn it off with
`--disable heap`"* is a decision they can make.

## Reading the result

Take the row whose allocation rate resembles your workload. Quoting a single
cell as "ptop's overhead" repeats the mistake this directory exists to correct.
