# eBPF PID-namespace fix — design

**Date:** 2026-05-19
**Status:** approved (brainstorming) → ready for implementation plan

---

## 1. Problem & root cause

On WSL2 (and inside Docker/LXC) every eBPF collector reports nothing. CPU and
syscalls show empty because they have no `/proc` fallback; threads, memory,
io-throughput, io-wait, fds and network still look populated because they have
`/proc`-derived data.

**Root cause:** WSL2 runs the whole distro inside a nested PID namespace. ptop's
eBPF programs filter events with:

```c
__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
if (tgid != *target) return 0;
```

`bpf_get_current_pid_tgid()` returns the PID in the **initial** PID namespace.
The `--pid` the user passes (and everything `ps`/`top`/`/proc` show inside the
distro) is the PID in the **distro's** namespace. On a normal host both are the
same namespace; under WSL2 they differ, so the comparison never matches.

**Evidence (instrumented diagnostic, run as root on WSL2):** the BPF programs
load, attach and run (`sys_enter` fired 301,723×, `perf_event` 4,797×); the
`target_pid` map held the correct value (`175347`); but `tgid == target` matched
**0 times** while the process did 279,829 `write` syscalls. The process's PID
namespace is `pid:[4026532221]` — the kernel's initial namespace is always
`pid:[4026531836]`.

This affects all 7 eBPF programs: cpu, syscalls, io, network, memory, futex
(uniform `is_X_target()` helper) and threads (a TID whitelist matched against
`sched_switch`'s root-namespace TIDs).

## 2. Goal & non-goals

**Goal:** all 7 eBPF collectors filter the target process correctly when ptop
runs inside a nested PID namespace, with **zero behavior change** on a native
Linux host in the root namespace.

**Non-goals (out of scope):**

- Hardening `model.go` to fall back to `/proc` when the eBPF CPU collector
  starts successfully but yields `0`. The namespace fix makes eBPF work; a
  "is 0% real or broken?" heuristic adds complexity without need. Deferred.
- macOS: untouched. All eBPF code is `//go:build linux && ebpf`; the macOS
  libproc/Mach path never compiles it.

## 3. Approach

Replace `bpf_get_current_pid_tgid()` with **`bpf_get_ns_current_pid_tgid(dev,
ino, &nsdata, sizeof(nsdata))`** (kernel 5.7+; ptop already requires 5.8+). The
helper returns the pid/tgid of the current task **as seen within the PID
namespace identified by (dev, ino)**.

The fix is a single uniform code path — there is no "WSL branch". On a native
host the target's `/proc/<pid>/ns/pid` resolves to the initial namespace, and
the helper returns exactly what `bpf_get_current_pid_tgid()` returned before.

The namespace logic is centralized in **one shared C header** and **one shared
Go resolver**, eliminating the 6–7× duplicated `is_X_target()` pattern.

## 4. Shared components

### 4.1 C header — `internal/bpf/programs/target.bpf.h` (new)

```c
#ifndef PTOP_TARGET_BPF_H
#define PTOP_TARGET_BPF_H
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Written by the Go loader. dev+ino identify the target's PID namespace;
 * pid is the target tgid as seen WITHIN that namespace. */
struct target_filter {
    __u32 pid;
    __u32 _pad;
    __u64 dev;
    __u64 ino;
};

/* 1 if the current task belongs to the target process, resolving pids
 * inside the target's PID namespace (correct under WSL2/containers). */
static __always_inline int pid_is_target(void *target_map) {
    __u32 key = 0;
    struct target_filter *tf = bpf_map_lookup_elem(target_map, &key);
    if (!tf || tf->pid == 0) return 0;
    struct bpf_pidns_info ns = {};
    if (bpf_get_ns_current_pid_tgid(tf->dev, tf->ino, &ns, sizeof(ns)) != 0)
        return 0;
    return ns.tgid == tf->pid;
}

/* Variant that also yields the namespace-local pid/tgid (used by threads).
 * Returns 1 and fills *out when the current task is the target. */
static __always_inline int pid_target_ns(void *target_map,
                                          struct bpf_pidns_info *out) {
    __u32 key = 0;
    struct target_filter *tf = bpf_map_lookup_elem(target_map, &key);
    if (!tf || tf->pid == 0) return 0;
    if (bpf_get_ns_current_pid_tgid(tf->dev, tf->ino, out, sizeof(*out)) != 0)
        return 0;
    return out->tgid == tf->pid;
}
#endif
```

`struct bpf_pidns_info { __u32 pid; __u32 tgid; }` comes from `<linux/bpf.h>`,
already included by every program. `#include "target.bpf.h"` resolves via
clang's same-directory search for quoted includes — no Makefile change.

### 4.2 Go resolver — `internal/bpf/target.go` (new, `//go:build linux && ebpf`)

```go
// targetFilter mirrors `struct target_filter` byte-for-byte (24 bytes).
type targetFilter struct {
    Pid uint32
    _   uint32
    Dev uint64
    Ino uint64
}

// resolveTarget builds the filter for pid: its tgid plus the device+inode
// of its PID namespace. On a native host in the root namespace this resolves
// to the initial pidns, so the BPF-side comparison is identical to the old
// bpf_get_current_pid_tgid() path.
func resolveTarget(pid int) (targetFilter, error) {
    var st unix.Stat_t
    if err := unix.Stat(fmt.Sprintf("/proc/%d/ns/pid", pid), &st); err != nil {
        return targetFilter{}, fmt.Errorf("stat pid namespace of %d: %w", pid, err)
    }
    return targetFilter{Pid: uint32(pid), Dev: st.Dev, Ino: st.Ino}, nil
}

// writeTargetFilter writes the resolved filter into an ARRAY[1] map at key 0.
func writeTargetFilter(m *ebpf.Map, tf targetFilter) error {
    var key uint32 = 0
    return m.Update(&key, &tf, ebpf.UpdateAny)
}
```

### 4.3 Data flow

`OpenXTracer(pid)` → load collection → `resolveTarget(pid)` (`stat` the ns) →
`writeTargetFilter(targetMap, tf)` → attach. Per event at runtime:
`pid_is_target(&X_target_pid)` → the kernel projects the current task's pid
into the target's namespace and compares.

## 5. The six uniform collectors — cpu, syscalls, io, network, memory, futex

Mechanical, identical change per collector:

- **`.bpf.c`:** `#include "target.bpf.h"`; delete the local `is_X_target()`
  helper; the `X_target_pid` map value type changes from `__u32` to
  `struct target_filter`. `cpu.bpf.c` has the filter inline in
  `handle_perf_event` — it becomes `if (!pid_is_target(&cpu_target_pid)) return 0;`.
  All other call sites become `pid_is_target(&X_target_pid)`.
- **loader (`.go`):** replace the `key`/`val`/`Update` block with
  `resolveTarget(pid)` + `writeTargetFilter(targetMap, tf)`, propagating any
  error through `t.Close()` + return (same shape as today).

Map names stay (`cpu_target_pid`, `net_target_pid`, …) to keep the diff small;
only the value type changes.

**Unchanged:** `pid_tgid` used as *keys* of in-flight maps (`enter_ts` in
syscalls, `io_inflight_map`, `futex_inflight`) keeps `bpf_get_current_pid_tgid()`
— those only need enter↔exit consistency, not namespace correctness.

## 6. The threads collector

`threads.bpf.c` filters with a TID whitelist (`tracked_tids`, populated by Go
from `/proc/<pid>/task/`) matched against `sched_switch`'s `prev_pid`/`next_pid`
— which are root-namespace TIDs. No CO-RE is needed to fix it.

`sched_switch` fires with `current == prev` (already documented in the file's
header comment). So `bpf_get_ns_current_pid_tgid()` resolves `prev`. The `next`
side is recovered from a self-populated mapping built on the `prev` side.

- **`threads.bpf.c`:**
  - `threads_target_pid` value type → `struct target_filter`.
  - Remove the `tracked_tids` map and `is_tracked()`.
  - Add `root2ns`: `BPF_MAP_TYPE_LRU_HASH`, key `__u32` (root-ns tid), value
    `__u32` (ns-local tid), `max_entries` 8192. LRU evicts dead TIDs by itself.
  - `handle_sched_switch`:
    - `prev` (= current): `pid_target_ns(&threads_target_pid, &ns)`. If it is a
      target thread, record `root2ns[ctx->prev_pid] = ns.pid`, then do off-CPU
      accounting + `ctx_switches++` on `tid_state[ns.pid]`.
    - `next`: look up `root2ns[ctx->next_pid]`; if present, do on-CPU accounting
      on `tid_state[<ns-local tid>]`.
  - `tid_state` stays keyed by **ns-local tid** — Go-side correlation unchanged.
  - Warm-up: a brand-new thread is learned the first time it is `prev` (one
    context switch). The original code already accepted a ~1s learning window;
    this is strictly better.
- **`threads.go`:** remove `UpdateTrackedTIDs()` and the `trackedMap` field;
  write the `target_filter` via the shared resolver; add `PruneDeadTIDs(live
  []int)` that deletes `tid_state` entries whose ns-local tid is not in `live`
  — this inherits the orphan/recycled-TID cleanup that lived inside
  `UpdateTrackedTIDs`.
- **`threads_ebpf.go`:** the periodic `UpdateTrackedTIDs` call site becomes
  `PruneDeadTIDs` (the collector already walks `/proc/<pid>/task/` each cycle,
  so it has the live ns-local TID set).

## 7. Non-regression on native Linux

The user's primary concern. Why native Linux (root namespace) cannot silently
regress, and how each real risk is covered:

- **One code path.** There is no WSL-specific branch. On a native host
  `/proc/<pid>/ns/pid` is the initial namespace; `bpf_get_ns_current_pid_tgid`
  with the initial ns's (dev, ino) returns the same pid/tgid as
  `bpf_get_current_pid_tgid`. Native is the depth-0 degenerate case of the same
  logic the WSL test exercises at depth 1.
- **CI guards native Linux automatically.** `.github/workflows/ci.yml` runs on
  `ubuntu-latest` (native, root namespace): `make gen` + `vet`/`test`/`build`
  for both the default and `-tags=ebpf` lanes. The new `target_test.go` runs
  there on every PR.
- **Real regression surface #1 — `struct target_filter` ABI.** A C↔Go layout
  mismatch would write garbage and break the filter everywhere, native
  included. Covered by a unit test asserting `unsafe.Sizeof(targetFilter{}) ==
  24` and field offsets, run in CI on native Linux.
- **Real regression surface #2 — the threads rewrite.** Removing
  `tracked_tids`/`UpdateTrackedTIDs` and adding `root2ns` is the only
  substantive *logic* change; it changes native behavior too. It must be
  verified end-to-end on a native Linux host (F4 panel showing per-thread CPU%
  and context switches), not only on WSL.
- **No silent failure on the map value-type change.** cilium/ebpf's `Map.Update`
  checks the value size against the map spec; a loader writing the wrong type
  fails loudly at `OpenXTracer` time rather than degrading silently.

## 8. Error handling & edge cases

- **Kernel version:** `bpf_get_ns_current_pid_tgid` is 5.7+; ptop already
  requires 5.8+ (`CapStatus.KernelSupportsBPF`). No new floor, no new fallback.
- **`resolveTarget` failure** (target exited between launch and load): `stat`
  fails → `OpenXTracer` returns an error → the existing `model.go` fallback
  (`/proc` or mock) takes over.
- **Helper returns non-zero at runtime** (current task not in the target's ns,
  e.g. the WSL root-namespace processes): treated as "not target" → `return 0`.
- **`struct target_filter` layout:** `u32, u32, u64, u64` = 24 bytes, 8-aligned;
  Go struct uses an explicit `_ uint32` pad. Asserted by a unit test.

## 9. Testing & verification

**Automated, no root (this host + CI):**

- TDD unit tests in `internal/bpf/target_test.go` (`//go:build linux && ebpf`):
  `resolveTarget` returns non-zero Dev/Ino and `Pid == os.Getpid()` for
  `/proc/self`; `unsafe.Sizeof(targetFilter{}) == 24`. Tests written first.
- `make gen` — all 7 `.bpf.c` compile against the new shared header.
- `go vet ./...` and `go vet -tags=ebpf ./...`.
- `go test -race ./...` and `go test -race -tags=ebpf ./...`.
- All of the above also run in CI on native Linux (root namespace).

**Manual, requires root (the user):**

- On **WSL2**: `sudo ./bin/ptop --pid <PID>` — F1 shows real CPU%, F2 populates
  syscalls, the `?` overlay shows `real via eBPF` for all 7 subsystems.
- On a **native Linux host**: the same end-to-end check, with explicit
  attention to the F4 threads panel (the largest logic change).
- `make ebpf-selftest` (below) on both for a fast pass/fail.

No claim of "works on WSL / works natively" is made until the user confirms the
manual runs.

## 10. ebpf-selftest tool

Commit a trimmed version of the throwaway diagnostic as `cmd/ebpfselftest`
(`//go:build linux && ebpf`) plus a `make ebpf-selftest` target. It opens the
cpu and syscalls tracers against its own PID, generates a known workload (CPU
burn + `write` syscalls), and prints per-collector pass/fail with counts. It is
a permanent self-diagnostic for anyone running ptop in a container or WSL.

## 11. Files touched

**New (4):**
- `internal/bpf/programs/target.bpf.h`
- `internal/bpf/target.go`
- `internal/bpf/target_test.go`
- `cmd/ebpfselftest/main.go`

**Modified `.bpf.c` (7):** cpu, syscalls, io, network, memory, threads, futex.

**Modified loaders (7):** cpu.go, syscalls.go, io.go, network.go, memory.go,
threads.go, futex.go.

**Modified collector (1):** `threads_ebpf.go` (call-site swap).

**Modified build (1):** `Makefile` (add `ebpf-selftest` target; add the new
`.bpf.h` as a prerequisite of the `.bpf.o` rule so edits to it trigger a
rebuild).

**Regenerated:** all `internal/bpf/programs/*.bpf.o` via `make gen`.

The `*_stub.go` files (non-eBPF lane) do not reference the new code; the
implementation plan confirms threads stub parity after the `UpdateTrackedTIDs`
removal.

## 12. Implementation order

1. Shared components: `target.bpf.h`, `target.go`, `target_test.go` (TDD).
2. The six uniform collectors (`.bpf.c` + loader), one at a time, `make gen`
   after each.
3. The threads collector (`.bpf.c`, `threads.go`, `threads_ebpf.go`).
4. `cmd/ebpfselftest` + `Makefile` target.
5. Full verification: both lanes vet/test/build, `make gen`; hand off to the
   user for the root runs on WSL2 and native Linux.
