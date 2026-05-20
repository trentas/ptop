# eBPF PID-namespace fix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make ptop's 7 eBPF collectors filter the target process correctly inside nested PID namespaces (WSL2, Docker, LXC), with zero behavior change on native Linux.

**Architecture:** Replace `bpf_get_current_pid_tgid()` (root-namespace PIDs) with `bpf_get_ns_current_pid_tgid()` (PIDs within a given namespace) across all eBPF programs. The namespace logic is centralized in one shared C header (`target.bpf.h`) and one shared Go resolver (`target.go`). The loader stats `/proc/<pid>/ns/pid` to obtain the namespace device+inode.

**Tech Stack:** Go 1.22, cilium/ebpf, clang BPF target, golang.org/x/sys/unix.

**Design spec:** `docs/superpowers/specs/2026-05-19-ebpf-pidns-fix-design.md`

---

## File Structure

**New files:**
- `internal/bpf/programs/target.bpf.h` — shared `struct target_filter` + `pid_is_target()` / `pid_target_ns()` helpers. Included by every `.bpf.c`.
- `internal/bpf/target.go` — `targetFilter` Go struct + `resolveTarget()` + `writeTargetFilter()`. (`//go:build linux && ebpf`)
- `internal/bpf/target_test.go` — unit tests for `resolveTarget` and struct layout. (`//go:build linux && ebpf`)
- `cmd/ebpfselftest/main.go` — root-only eBPF self-diagnostic. (`//go:build linux && ebpf`)
- `cmd/ebpfselftest/stub.go` — non-eBPF stub so the package always builds. (`//go:build !linux || !ebpf`)

**Modified files:**
- `internal/bpf/programs/{cpu,syscalls,io,network,memory,futex,threads}.bpf.c` — use the shared header.
- `internal/bpf/{cpu,syscalls,io,network,memory,futex,threads}.go` — use `resolveTarget`/`writeTargetFilter`.
- `internal/bpf/threads_stub.go` — `UpdateTrackedTIDs` → `PruneDeadTIDs` (API parity).
- `internal/collector/threads_ebpf.go` — call-site swap.
- `Makefile` — header prerequisite + `ebpf-selftest` target.
- `CLAUDE.md` — document the new header and tool.

**Regenerated (not committed, git-ignored):** `internal/bpf/programs/*.bpf.o`.

---

## Task 1: Shared Go resolver

Builds the namespace-aware target filter on the Go side. Fully testable without root.

**Files:**
- Create: `internal/bpf/target.go`
- Test: `internal/bpf/target_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/bpf/target_test.go`:

```go
//go:build linux && ebpf

package bpf

import (
	"os"
	"testing"
	"unsafe"
)

// The Go targetFilter must match `struct target_filter` in target.bpf.h
// byte-for-byte, or the loader writes garbage into the BPF map.
func TestTargetFilterSize(t *testing.T) {
	if got := unsafe.Sizeof(targetFilter{}); got != 24 {
		t.Fatalf("sizeof(targetFilter) = %d, want 24", got)
	}
}

func TestResolveTargetSelf(t *testing.T) {
	tf, err := resolveTarget(os.Getpid())
	if err != nil {
		t.Fatalf("resolveTarget(self): %v", err)
	}
	if tf.Pid != uint32(os.Getpid()) {
		t.Errorf("Pid = %d, want %d", tf.Pid, os.Getpid())
	}
	if tf.Dev == 0 {
		t.Error("Dev = 0, want the nsfs device number")
	}
	if tf.Ino == 0 {
		t.Error("Ino = 0, want the pid-namespace inode")
	}
}

func TestResolveTargetMissingPID(t *testing.T) {
	if _, err := resolveTarget(0x7fffffff); err == nil {
		t.Error("resolveTarget(nonexistent pid) = nil error, want failure")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test -tags=ebpf ./internal/bpf/ -run TestResolveTarget -v`
Expected: FAIL — build error, `undefined: resolveTarget` and `undefined: targetFilter`.

- [ ] **Step 3: Write the implementation**

Create `internal/bpf/target.go`:

```go
//go:build linux && ebpf

package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// targetFilter mirrors `struct target_filter` in programs/target.bpf.h
// byte-for-byte (24 bytes: u32 pid, u32 pad, u64 dev, u64 ino).
type targetFilter struct {
	Pid uint32
	_   uint32
	Dev uint64
	Ino uint64
}

// resolveTarget builds the filter for pid: its tgid plus the device and
// inode of the PID namespace it lives in (/proc/<pid>/ns/pid).
//
// On a native host in the root namespace this resolves to the initial PID
// namespace, so the BPF-side bpf_get_ns_current_pid_tgid() call returns the
// same values bpf_get_current_pid_tgid() returned before — identical
// behavior. Inside a nested namespace (WSL2, containers) it resolves to that
// namespace, which is what makes the filter match.
func resolveTarget(pid int) (targetFilter, error) {
	var st unix.Stat_t
	if err := unix.Stat(fmt.Sprintf("/proc/%d/ns/pid", pid), &st); err != nil {
		return targetFilter{}, fmt.Errorf("stat pid namespace of %d: %w", pid, err)
	}
	return targetFilter{Pid: uint32(pid), Dev: st.Dev, Ino: st.Ino}, nil
}

// writeTargetFilter stores the resolved filter at key 0 of an ARRAY[1] map.
func writeTargetFilter(m *ebpf.Map, tf targetFilter) error {
	var key uint32 = 0
	return m.Update(&key, &tf, ebpf.UpdateAny)
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test -tags=ebpf ./internal/bpf/ -run TestResolveTarget -v`
Expected: PASS — `TestResolveTargetSelf`, `TestResolveTargetMissingPID` pass.

Run: `go test -tags=ebpf ./internal/bpf/ -run TestTargetFilterSize -v`
Expected: PASS.

- [ ] **Step 5: Vet**

Run: `go vet -tags=ebpf ./internal/bpf/`
Expected: no output (clean).

- [ ] **Step 6: Commit**

```bash
git add internal/bpf/target.go internal/bpf/target_test.go
git commit -m "feat(bpf): add namespace-aware target resolver"
```

---

## Task 2: Shared C header + cpu collector

Creates `target.bpf.h`, wires the Makefile, and converts the first collector (cpu) — which proves the header compiles.

**Files:**
- Create: `internal/bpf/programs/target.bpf.h`
- Modify: `Makefile`
- Modify: `internal/bpf/programs/cpu.bpf.c`
- Modify: `internal/bpf/cpu.go`

- [ ] **Step 1: Create the shared header**

Create `internal/bpf/programs/target.bpf.h`:

```c
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * target.bpf.h — namespace-aware target-process filter shared by every
 * ptop eBPF program.
 *
 * bpf_get_current_pid_tgid() returns PIDs in the INITIAL pid namespace.
 * ptop's --pid is a namespace-local PID (what /proc and ps show). Under a
 * nested pid namespace (WSL2, Docker, LXC) the two differ, so the old
 * `tgid == target` comparison never matched. bpf_get_ns_current_pid_tgid()
 * (kernel 5.7+) projects the current task's pid into a specific namespace,
 * identified by the (dev, ino) of /proc/<pid>/ns/pid.
 */
#ifndef PTOP_TARGET_BPF_H
#define PTOP_TARGET_BPF_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Written by the Go loader (see internal/bpf/target.go). dev+ino identify
 * the target's PID namespace; pid is the target tgid within that namespace. */
struct target_filter {
    __u32 pid;
    __u32 _pad;
    __u64 dev;
    __u64 ino;
};

/* pid_target_ns resolves the current task's pid/tgid inside the target's
 * namespace and writes them into *out. Returns 1 when the current task is
 * the target process, 0 otherwise. target_map is an ARRAY[1] of
 * struct target_filter. */
static __always_inline int pid_target_ns(void *target_map,
                                          struct bpf_pidns_info *out)
{
    __u32 key = 0;
    struct target_filter *tf = bpf_map_lookup_elem(target_map, &key);
    if (!tf || tf->pid == 0)
        return 0;
    if (bpf_get_ns_current_pid_tgid(tf->dev, tf->ino, out, sizeof(*out)) != 0)
        return 0;
    return out->tgid == tf->pid;
}

/* pid_is_target returns 1 when the current task belongs to the target
 * process. Use this anywhere the old is_*_target() helpers were used. */
static __always_inline int pid_is_target(void *target_map)
{
    struct bpf_pidns_info ns = {};
    return pid_target_ns(target_map, &ns);
}

#endif /* PTOP_TARGET_BPF_H */
```

- [ ] **Step 2: Make `.bpf.o` depend on the header**

In `Makefile`, find:

```make
BPF_OBJS := $(BPF_SRCS:.c=.o)

CLANG  ?= clang
```

Replace with:

```make
BPF_OBJS := $(BPF_SRCS:.c=.o)

# Every BPF object includes the shared filter header — editing it must
# trigger a rebuild (the %.bpf.o rule below only tracks the .c file).
$(BPF_OBJS): internal/bpf/programs/target.bpf.h

CLANG  ?= clang
```

- [ ] **Step 3: Convert `cpu.bpf.c`**

In `internal/bpf/programs/cpu.bpf.c`, find:

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";
```

Replace with:

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "target.bpf.h"

char LICENSE[] SEC("license") = "GPL";
```

In the same file, find:

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} cpu_target_pid SEC(".maps");
```

Replace with:

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct target_filter);
    __uint(max_entries, 1);
} cpu_target_pid SEC(".maps");
```

In the same file, find:

```c
SEC("perf_event")
int handle_perf_event(void *ctx)
{
    __u32 key = 0;
    __u32 *target = bpf_map_lookup_elem(&cpu_target_pid, &key);
    if (!target || *target == 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);
    if (tgid != *target)
        return 0;

    __u64 *count = bpf_map_lookup_elem(&cpu_target_samples, &key);
    if (count)
        __sync_fetch_and_add(count, 1);
    return 0;
}
```

Replace with:

```c
SEC("perf_event")
int handle_perf_event(void *ctx)
{
    if (!pid_is_target(&cpu_target_pid))
        return 0;

    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&cpu_target_samples, &key);
    if (count)
        __sync_fetch_and_add(count, 1);
    return 0;
}
```

- [ ] **Step 4: Convert `cpu.go`**

In `internal/bpf/cpu.go`, find:

```go
	var key uint32 = 0
	val := uint32(pid)
	if err := targetMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
		t.Close()
		return nil, fmt.Errorf("set cpu_target_pid: %w", err)
	}
```

Replace with:

```go
	tf, err := resolveTarget(pid)
	if err != nil {
		t.Close()
		return nil, err
	}
	if err := writeTargetFilter(targetMap, tf); err != nil {
		t.Close()
		return nil, fmt.Errorf("set cpu_target_pid: %w", err)
	}
```

- [ ] **Step 5: Compile the BPF objects**

Run: `make gen`
Expected: success — all 7 `.bpf.c` compile, including `cpu.bpf.c` with the new header. No clang errors.

- [ ] **Step 6: Build, vet and test the eBPF lane**

Run: `go build -tags=ebpf -o /tmp/ptop-ebpf ./cmd/ptop`
Expected: success.

Run: `go vet -tags=ebpf ./...`
Expected: no output (clean).

Run: `go test -race -tags=ebpf ./...`
Expected: PASS (all packages, including `internal/bpf` tests from Task 1).

- [ ] **Step 7: Commit**

```bash
git add internal/bpf/programs/target.bpf.h Makefile internal/bpf/programs/cpu.bpf.c internal/bpf/cpu.go
git commit -m "fix(bpf): namespace-aware pid filter for cpu collector"
```

---

## Task 3: syscalls collector

**Files:**
- Modify: `internal/bpf/programs/syscalls.bpf.c`
- Modify: `internal/bpf/syscalls.go`

- [ ] **Step 1: Convert `syscalls.bpf.c`**

In `internal/bpf/programs/syscalls.bpf.c`, find:

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";
```

Replace with:

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "target.bpf.h"

char LICENSE[] SEC("license") = "GPL";
```

In the same file, find:

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} target_pid SEC(".maps");
```

Replace with:

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct target_filter);
    __uint(max_entries, 1);
} target_pid SEC(".maps");
```

In the same file, find:

```c
// is_target returns 1 if the current tgid is the configured target pid, 0 otherwise.
static __always_inline int is_target(void)
{
    __u32 key = 0;
    __u32 *target = bpf_map_lookup_elem(&target_pid, &key);
    if (!target || *target == 0)
        return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);
    return tgid == *target;
}
```

Replace with:

```c
// is_target returns 1 if the current task belongs to the target process,
// resolving pids inside the target's PID namespace (see target.bpf.h).
static __always_inline int is_target(void)
{
    return pid_is_target(&target_pid);
}
```

- [ ] **Step 2: Convert `syscalls.go`**

In `internal/bpf/syscalls.go`, find:

```go
	var key uint32 = 0
	val := uint32(pid)
	if err := targetMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
		t.Close()
		return nil, fmt.Errorf("set target_pid: %w", err)
	}
```

Replace with:

```go
	tf, err := resolveTarget(pid)
	if err != nil {
		t.Close()
		return nil, err
	}
	if err := writeTargetFilter(targetMap, tf); err != nil {
		t.Close()
		return nil, fmt.Errorf("set target_pid: %w", err)
	}
```

- [ ] **Step 3: Compile, build, vet, test**

Run: `make gen`
Expected: success.

Run: `go build -tags=ebpf -o /tmp/ptop-ebpf ./cmd/ptop && go vet -tags=ebpf ./... && go test -race -tags=ebpf ./...`
Expected: build success, vet clean, tests PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/bpf/programs/syscalls.bpf.c internal/bpf/syscalls.go
git commit -m "fix(bpf): namespace-aware pid filter for syscalls collector"
```

---

## Task 4: io collector

**Files:**
- Modify: `internal/bpf/programs/io.bpf.c`
- Modify: `internal/bpf/io.go`

- [ ] **Step 1: Convert `io.bpf.c`**

In `internal/bpf/programs/io.bpf.c`, find:

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";
```

Replace with:

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "target.bpf.h"

char LICENSE[] SEC("license") = "GPL";
```

In the same file, find:

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} io_target_pid SEC(".maps");
```

Replace with:

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct target_filter);
    __uint(max_entries, 1);
} io_target_pid SEC(".maps");
```

In the same file, find:

```c
static __always_inline int is_io_target(void)
{
    __u32 key = 0;
    __u32 *target = bpf_map_lookup_elem(&io_target_pid, &key);
    if (!target || *target == 0)
        return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);
    return tgid == *target;
}
```

Replace with:

```c
static __always_inline int is_io_target(void)
{
    return pid_is_target(&io_target_pid);
}
```

- [ ] **Step 2: Convert `io.go`**

In `internal/bpf/io.go`, find:

```go
	var key uint32 = 0
	val := uint32(pid)
	if err := targetMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
		t.Close()
		return nil, fmt.Errorf("set io_target_pid: %w", err)
	}
```

Replace with:

```go
	tf, err := resolveTarget(pid)
	if err != nil {
		t.Close()
		return nil, err
	}
	if err := writeTargetFilter(targetMap, tf); err != nil {
		t.Close()
		return nil, fmt.Errorf("set io_target_pid: %w", err)
	}
```

- [ ] **Step 3: Compile, build, vet, test**

Run: `make gen`
Expected: success.

Run: `go build -tags=ebpf -o /tmp/ptop-ebpf ./cmd/ptop && go vet -tags=ebpf ./... && go test -race -tags=ebpf ./...`
Expected: build success, vet clean, tests PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/bpf/programs/io.bpf.c internal/bpf/io.go
git commit -m "fix(bpf): namespace-aware pid filter for io collector"
```

---

## Task 5: network collector

**Files:**
- Modify: `internal/bpf/programs/network.bpf.c`
- Modify: `internal/bpf/network.go`

- [ ] **Step 1: Convert `network.bpf.c`**

In `internal/bpf/programs/network.bpf.c`, find:

```c
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";
```

Replace with:

```c
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "target.bpf.h"

char LICENSE[] SEC("license") = "GPL";
```

In the same file, find:

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} net_target_pid SEC(".maps");
```

Replace with:

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct target_filter);
    __uint(max_entries, 1);
} net_target_pid SEC(".maps");
```

In the same file, find:

```c
static __always_inline int is_net_target(void)
{
    __u32 key = 0;
    __u32 *target = bpf_map_lookup_elem(&net_target_pid, &key);
    if (!target || *target == 0)
        return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);
    return tgid == *target;
}
```

Replace with:

```c
static __always_inline int is_net_target(void)
{
    return pid_is_target(&net_target_pid);
}
```

- [ ] **Step 2: Convert `network.go`**

In `internal/bpf/network.go`, find:

```go
	var key uint32 = 0
	val := uint32(pid)
	if err := targetMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
		t.Close()
		return nil, fmt.Errorf("set net_target_pid: %w", err)
	}
```

Replace with:

```go
	tf, err := resolveTarget(pid)
	if err != nil {
		t.Close()
		return nil, err
	}
	if err := writeTargetFilter(targetMap, tf); err != nil {
		t.Close()
		return nil, fmt.Errorf("set net_target_pid: %w", err)
	}
```

- [ ] **Step 3: Compile, build, vet, test**

Run: `make gen`
Expected: success.

Run: `go build -tags=ebpf -o /tmp/ptop-ebpf ./cmd/ptop && go vet -tags=ebpf ./... && go test -race -tags=ebpf ./...`
Expected: build success, vet clean, tests PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/bpf/programs/network.bpf.c internal/bpf/network.go
git commit -m "fix(bpf): namespace-aware pid filter for network collector"
```

---

## Task 6: memory collector

**Files:**
- Modify: `internal/bpf/programs/memory.bpf.c`
- Modify: `internal/bpf/memory.go`

- [ ] **Step 1: Convert `memory.bpf.c`**

In `internal/bpf/programs/memory.bpf.c`, find:

```c
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";
```

Replace with:

```c
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "target.bpf.h"

char LICENSE[] SEC("license") = "GPL";
```

In the same file, find:

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} mem_target_pid SEC(".maps");
```

Replace with:

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct target_filter);
    __uint(max_entries, 1);
} mem_target_pid SEC(".maps");
```

In the same file, find:

```c
static __always_inline int is_mem_target(void)
{
    __u32 key = 0;
    __u32 *target = bpf_map_lookup_elem(&mem_target_pid, &key);
    if (!target || *target == 0)
        return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);
    return tgid == *target;
}
```

Replace with:

```c
static __always_inline int is_mem_target(void)
{
    return pid_is_target(&mem_target_pid);
}
```

- [ ] **Step 2: Convert `memory.go`**

In `internal/bpf/memory.go`, find:

```go
	var key uint32 = 0
	val := uint32(pid)
	if err := targetMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
		t.Close()
		return nil, fmt.Errorf("set mem_target_pid: %w", err)
	}
```

Replace with:

```go
	tf, err := resolveTarget(pid)
	if err != nil {
		t.Close()
		return nil, err
	}
	if err := writeTargetFilter(targetMap, tf); err != nil {
		t.Close()
		return nil, fmt.Errorf("set mem_target_pid: %w", err)
	}
```

- [ ] **Step 3: Compile, build, vet, test**

Run: `make gen`
Expected: success.

Run: `go build -tags=ebpf -o /tmp/ptop-ebpf ./cmd/ptop && go vet -tags=ebpf ./... && go test -race -tags=ebpf ./...`
Expected: build success, vet clean, tests PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/bpf/programs/memory.bpf.c internal/bpf/memory.go
git commit -m "fix(bpf): namespace-aware pid filter for memory collector"
```

---

## Task 7: futex collector

**Files:**
- Modify: `internal/bpf/programs/futex.bpf.c`
- Modify: `internal/bpf/futex.go`

- [ ] **Step 1: Convert `futex.bpf.c`**

In `internal/bpf/programs/futex.bpf.c`, find:

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";
```

Replace with:

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "target.bpf.h"

char LICENSE[] SEC("license") = "GPL";
```

In the same file, find:

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} futex_target_pid SEC(".maps");
```

Replace with:

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct target_filter);
    __uint(max_entries, 1);
} futex_target_pid SEC(".maps");
```

In the same file, find:

```c
static __always_inline int is_futex_target(void)
{
    __u32 key = 0;
    __u32 *target = bpf_map_lookup_elem(&futex_target_pid, &key);
    if (!target || *target == 0)
        return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);
    return tgid == *target;
}
```

Replace with:

```c
static __always_inline int is_futex_target(void)
{
    return pid_is_target(&futex_target_pid);
}
```

> Note: `handle_enter_futex` / `handle_exit_futex` keep using
> `bpf_get_current_pid_tgid()` as the key of the `futex_inflight` map — that
> only needs enter↔exit consistency, not namespace correctness. Do not change
> those lines.

- [ ] **Step 2: Convert `futex.go`**

In `internal/bpf/futex.go`, find:

```go
	var key uint32 = 0
	val := uint32(pid)
	if err := targetMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
		t.Close()
		return nil, fmt.Errorf("set futex_target_pid: %w", err)
	}
```

Replace with:

```go
	tf, err := resolveTarget(pid)
	if err != nil {
		t.Close()
		return nil, err
	}
	if err := writeTargetFilter(targetMap, tf); err != nil {
		t.Close()
		return nil, fmt.Errorf("set futex_target_pid: %w", err)
	}
```

- [ ] **Step 3: Compile, build, vet, test**

Run: `make gen`
Expected: success.

Run: `go build -tags=ebpf -o /tmp/ptop-ebpf ./cmd/ptop && go vet -tags=ebpf ./... && go test -race -tags=ebpf ./...`
Expected: build success, vet clean, tests PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/bpf/programs/futex.bpf.c internal/bpf/futex.go
git commit -m "fix(bpf): namespace-aware pid filter for futex collector"
```

---

## Task 8: threads collector

The threads program filters by a TID whitelist matched against `sched_switch`'s
root-namespace TIDs. It is replaced by: a `target_filter` check on `prev`
(== `current` at the tracepoint) plus a self-populated `root2ns` LRU map that
recovers the `next` thread's namespace-local TID. `tid_state` stays keyed by
namespace-local TIDs, so the Go-side correlation is unchanged.

**Files:**
- Modify (full replace): `internal/bpf/programs/threads.bpf.c`
- Modify (full replace): `internal/bpf/threads.go`
- Modify: `internal/bpf/threads_stub.go`
- Modify: `internal/collector/threads_ebpf.go`

- [ ] **Step 1: Replace `threads.bpf.c`**

Replace the entire contents of `internal/bpf/programs/threads.bpf.c` with:

```c
// SPDX-License-Identifier: GPL-2.0
//
// threads.bpf.c — tracks scheduler transitions (on-CPU ↔ off-CPU) of the
// target PID's threads via the sched:sched_switch tracepoint.
//
// Why sched_switch and not /proc/<pid>/task/<tid>/stat?
//   /proc gives cumulative utime+stime sampled at 1Hz — bad granularity
//   for threads that oscillate quickly between running/blocked. The
//   tracepoint fires on EVERY context switch, so on_cpu_ns reflects
//   exactly what the kernel measured, in real time.
//
// Maps:
//   threads_target_pid  ARRAY[1]   struct target_filter (written by Go)
//   root2ns             LRU_HASH   root-ns tid → namespace-local tid
//   tid_state           HASH       ns-local tid → struct thread_state
//
// PID-namespace handling:
//   sched_switch delivers prev_pid/next_pid as ROOT-namespace TIDs, but the
//   Go side and tid_state work in the target's namespace-local TIDs. At the
//   tracepoint `current` == prev, so pid_target_ns() resolves prev's
//   namespace-local tid; that {root_tid → ns_tid} pair is cached in root2ns.
//   The `next` side then recovers the ns-local tid by looking up next_pid in
//   root2ns (learned the previous time that thread was scheduled out). A
//   brand-new thread is learned the first time it is `prev` — one context
//   switch of warm-up, which the UI tolerates.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "target.bpf.h"

char LICENSE[] SEC("license") = "GPL";

// Stable layout of the sched:sched_switch tracepoint.
// /sys/kernel/debug/tracing/events/sched/sched_switch/format
struct sched_switch_args {
    unsigned long long _pad;     // common_type/flags/preempt_count/pid (8B)
    char prev_comm[16];          // offset 8
    int prev_pid;                // offset 24
    int prev_prio;               // offset 28
    long prev_state;             // offset 32
    char next_comm[16];          // offset 40
    int next_pid;                // offset 56
    int next_prio;               // offset 60
};

struct thread_state {
    __u64 last_on_cpu_ns;
    __u64 last_off_cpu_ns;
    __u64 on_cpu_ns_total;
    __u64 off_cpu_ns_total;
    __u64 ctx_switches;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct target_filter);
    __uint(max_entries, 1);
} threads_target_pid SEC(".maps");

// root2ns maps a root-namespace TID to the target's namespace-local TID.
// Self-populated from the `prev` side of sched_switch; LRU evicts dead TIDs.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 8192);
} root2ns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct thread_state);
    __uint(max_entries, 8192);
} tid_state SEC(".maps");

// Get-or-create entry in tid_state. Returns ptr (always non-null on success).
// On update failure (pathological case), returns NULL.
static __always_inline struct thread_state *get_or_create_state(__u32 tid)
{
    struct thread_state *s = bpf_map_lookup_elem(&tid_state, &tid);
    if (s)
        return s;
    struct thread_state zero = {};
    bpf_map_update_elem(&tid_state, &tid, &zero, BPF_ANY);
    return bpf_map_lookup_elem(&tid_state, &tid);
}

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct sched_switch_args *ctx)
{
    __u64 now = bpf_ktime_get_ns();

    // prev == current at sched_switch. If it belongs to the target process,
    // cache its root→ns TID mapping and do off-CPU accounting.
    struct bpf_pidns_info ns = {};
    if (pid_target_ns(&threads_target_pid, &ns)) {
        __u32 root_tid = (__u32)ctx->prev_pid;
        __u32 ns_tid = ns.pid;
        bpf_map_update_elem(&root2ns, &root_tid, &ns_tid, BPF_ANY);

        struct thread_state *s = get_or_create_state(ns_tid);
        if (s) {
            if (s->last_on_cpu_ns != 0) {
                __u64 delta = now - s->last_on_cpu_ns;
                __sync_fetch_and_add(&s->on_cpu_ns_total, delta);
            }
            s->last_off_cpu_ns = now;
            __sync_fetch_and_add(&s->ctx_switches, 1);
        }
    }

    // next entering CPU: recover its ns-local TID from root2ns (learned the
    // last time it was scheduled out).
    __u32 next_root = (__u32)ctx->next_pid;
    __u32 *next_ns = bpf_map_lookup_elem(&root2ns, &next_root);
    if (next_ns) {
        struct thread_state *s = get_or_create_state(*next_ns);
        if (s) {
            if (s->last_off_cpu_ns != 0) {
                __u64 delta = now - s->last_off_cpu_ns;
                __sync_fetch_and_add(&s->off_cpu_ns_total, delta);
            }
            s->last_on_cpu_ns = now;
        }
    }
    return 0;
}
```

- [ ] **Step 2: Replace `threads.go`**

Replace the entire contents of `internal/bpf/threads.go` with:

```go
//go:build linux && ebpf

package bpf

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed programs/threads.bpf.o
var threadsBPFObj []byte

// ThreadState mirrors `struct thread_state` in programs/threads.bpf.c 1:1.
// 40 bytes aligned (5 × u64).
type ThreadState struct {
	LastOnCpuNs   uint64
	LastOffCpuNs  uint64
	OnCpuNsTotal  uint64
	OffCpuNsTotal uint64
	CtxSwitches   uint64
}

// ThreadsTracer loads threads.bpf.o, attaches sched:sched_switch, and exposes
// Stats() to read tid_state (keyed by the target's namespace-local TIDs).
type ThreadsTracer struct {
	coll     *ebpf.Collection
	link     link.Link
	stateMap *ebpf.Map
}

func OpenThreadsTracer(pid int) (*ThreadsTracer, error) {
	if pid <= 0 {
		return nil, errors.New("invalid pid")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(threadsBPFObj))
	if err != nil {
		return nil, fmt.Errorf("parse threads BPF object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load threads collection: %w", err)
	}
	t := &ThreadsTracer{coll: coll}

	targetMap := coll.Maps["threads_target_pid"]
	if targetMap == nil {
		t.Close()
		return nil, errors.New("threads_target_pid map missing")
	}
	tf, err := resolveTarget(pid)
	if err != nil {
		t.Close()
		return nil, err
	}
	if err := writeTargetFilter(targetMap, tf); err != nil {
		t.Close()
		return nil, fmt.Errorf("set threads_target_pid: %w", err)
	}

	t.stateMap = coll.Maps["tid_state"]
	if t.stateMap == nil {
		t.Close()
		return nil, errors.New("tid_state map missing")
	}

	prog := coll.Programs["handle_sched_switch"]
	if prog == nil {
		t.Close()
		return nil, errors.New("handle_sched_switch program missing")
	}
	l, err := link.Tracepoint("sched", "sched_switch", prog, nil)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("attach sched/sched_switch: %w", err)
	}
	t.link = l

	return t, nil
}

// PruneDeadTIDs deletes tid_state entries for TIDs no longer alive, so a
// recycled TID does not inherit stale counters. `live` holds the
// namespace-local TIDs currently present under /proc/<pid>/task/.
func (t *ThreadsTracer) PruneDeadTIDs(live []int) error {
	if t == nil || t.stateMap == nil {
		return errors.New("tracer not initialized")
	}
	alive := make(map[uint32]struct{}, len(live))
	for _, tid := range live {
		if tid > 0 {
			alive[uint32(tid)] = struct{}{}
		}
	}
	var dead []uint32
	var k uint32
	var v ThreadState
	iter := t.stateMap.Iterate()
	for iter.Next(&k, &v) {
		if _, ok := alive[k]; !ok {
			dead = append(dead, k)
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for i := range dead {
		_ = t.stateMap.Delete(&dead[i])
	}
	return nil
}

// Stats returns a complete snapshot of the tid_state map, keyed by the
// target's namespace-local TIDs.
func (t *ThreadsTracer) Stats() (map[uint32]ThreadState, error) {
	if t == nil || t.stateMap == nil {
		return nil, errors.New("tracer not initialized")
	}
	out := make(map[uint32]ThreadState, 64)
	var k uint32
	var v ThreadState
	iter := t.stateMap.Iterate()
	for iter.Next(&k, &v) {
		out[k] = v
	}
	if err := iter.Err(); err != nil {
		return out, err
	}
	return out, nil
}

func (t *ThreadsTracer) Close() error {
	if t == nil {
		return nil
	}
	if t.link != nil {
		_ = t.link.Close()
		t.link = nil
	}
	if t.coll != nil {
		t.coll.Close()
		t.coll = nil
		t.stateMap = nil
	}
	return nil
}
```

- [ ] **Step 3: Update the non-eBPF stub**

In `internal/bpf/threads_stub.go`, find:

```go
func (*ThreadsTracer) UpdateTrackedTIDs([]int) error    { return errThreadsStub }
```

Replace with:

```go
func (*ThreadsTracer) PruneDeadTIDs([]int) error        { return errThreadsStub }
```

- [ ] **Step 4: Update the collector call site**

In `internal/collector/threads_ebpf.go`, find:

```go
//   - sync tracked_tids in the BPF map (add new ones, remove stragglers)
```

Replace with:

```go
//   - prune tid_state for TIDs that have exited
```

In the same file, find:

```go
	// Sync tracked_tids in the BPF map.
	if err := c.tracer.UpdateTrackedTIDs(tidList); err != nil {
		// Not fatal: keep publishing /proc data even if the sync fails.
		_ = err
	}
```

Replace with:

```go
	// Prune tid_state for threads that exited since the last tick.
	if err := c.tracer.PruneDeadTIDs(tidList); err != nil {
		// Not fatal: keep publishing /proc data even if the prune fails.
		_ = err
	}
```

- [ ] **Step 5: Compile, build, vet, test (both lanes)**

Run: `make gen`
Expected: success.

Run: `go build -tags=ebpf -o /tmp/ptop-ebpf ./cmd/ptop && go vet -tags=ebpf ./... && go test -race -tags=ebpf ./...`
Expected: build success, vet clean, tests PASS.

Run: `go build -o /tmp/ptop ./cmd/ptop && go vet ./... && go test -race ./...`
Expected: build success, vet clean, tests PASS (the default lane uses `threads_stub.go`).

- [ ] **Step 6: Commit**

```bash
git add internal/bpf/programs/threads.bpf.c internal/bpf/threads.go internal/bpf/threads_stub.go internal/collector/threads_ebpf.go
git commit -m "fix(bpf): namespace-aware pid filter for threads collector"
```

---

## Task 9: ebpf-selftest diagnostic tool

A root-only tool that verifies the eBPF collectors can observe the target
process — a permanent self-diagnostic for container/WSL users.

**Files:**
- Create: `cmd/ebpfselftest/main.go`
- Create: `cmd/ebpfselftest/stub.go`
- Modify: `Makefile`

- [ ] **Step 1: Create the tool**

Create `cmd/ebpfselftest/main.go`:

```go
//go:build linux && ebpf

// ebpf-selftest verifies that ptop's eBPF collectors can actually observe
// the target process — useful inside containers / WSL, where nested PID
// namespaces historically broke the filter. Run as root:
//
//	sudo ./bin/ebpf-selftest
//
// It targets its own process, generates a known workload (CPU burn + write
// syscalls), and reports whether the eBPF counters moved.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/trentas/ptop/internal/bpf"
)

func main() {
	if d := bpf.GetCapStatus().Diagnose(); d != "" {
		fmt.Fprint(os.Stderr, d)
		os.Exit(1)
	}

	pid := os.Getpid()
	fmt.Printf("ptop eBPF self-test — target = self (pid %d)\n\n", pid)

	cpuT, err := bpf.OpenCPUTracer(pid)
	if err != nil {
		fmt.Println("FAIL  cpu: OpenCPUTracer:", err)
		os.Exit(1)
	}
	defer cpuT.Close()

	scT, err := bpf.OpenSyscallTracer(pid)
	if err != nil {
		fmt.Println("FAIL  syscalls: OpenSyscallTracer:", err)
		os.Exit(1)
	}
	defer scT.Close()

	// Workload: CPU burn + real write(2) syscalls for 3 seconds.
	devnull, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		fmt.Println("FAIL  cannot open /dev/null:", err)
		os.Exit(1)
	}
	buf := []byte("x")
	var spin uint64
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for i := 0; i < 50000; i++ {
			spin++
		}
		_, _ = devnull.Write(buf)
	}
	devnull.Close()
	_ = spin

	failed := false

	samples, _ := cpuT.SampleCount()
	if samples > 0 {
		fmt.Printf("PASS  cpu:      %d on-CPU samples observed\n", samples)
	} else {
		fmt.Println("FAIL  cpu:      0 samples — the eBPF filter did not match this process")
		failed = true
	}

	stats, _ := scT.Stats()
	var total uint64
	for _, s := range stats {
		total += s.Count
	}
	if total > 0 {
		fmt.Printf("PASS  syscalls: %d events across %d syscall ids\n", total, len(stats))
	} else {
		fmt.Println("FAIL  syscalls: 0 events — the eBPF filter did not match this process")
		failed = true
	}

	if failed {
		fmt.Println("\neBPF self-test FAILED")
		os.Exit(1)
	}
	fmt.Println("\neBPF self-test PASSED")
}
```

Create `cmd/ebpfselftest/stub.go`:

```go
//go:build !linux || !ebpf

// Stub so `go build ./...` / `go vet ./...` succeed in the default lane —
// the real self-test only exists in the Linux eBPF build.
package main

import "fmt"

func main() {
	fmt.Println("ebpf-selftest requires a Linux build with -tags=ebpf")
}
```

- [ ] **Step 2: Add the Makefile target**

In `Makefile`, find:

```make
.PHONY: all build build-ebpf run gen clean dev test test-all vet lint install install-bare install-ebpf uninstall
```

Replace with:

```make
.PHONY: all build build-ebpf run gen clean dev test test-all vet lint install install-bare install-ebpf uninstall ebpf-selftest
```

In `Makefile`, find:

```make
# /proc-only mode — no root, no eBPF
dev: build
	./bin/$(BINARY) --pid $(PID) --no-ebpf
```

Replace with:

```make
# /proc-only mode — no root, no eBPF
dev: build
	./bin/$(BINARY) --pid $(PID) --no-ebpf

# ebpf-selftest builds the eBPF self-diagnostic. Run the result as root:
# `sudo ./bin/ebpf-selftest` — it reports whether the eBPF collectors can
# observe the target process (useful inside containers / WSL).
ebpf-selftest: gen
	go build -tags=ebpf -o bin/ebpf-selftest ./cmd/ebpfselftest
	@echo "built bin/ebpf-selftest — run as root: sudo ./bin/ebpf-selftest"
```

- [ ] **Step 3: Build both lanes**

Run: `go build -tags=ebpf -o /tmp/selftest-ebpf ./cmd/ebpfselftest`
Expected: success.

Run: `go build -o /tmp/selftest ./cmd/ebpfselftest`
Expected: success (uses `stub.go`).

Run: `go vet ./... && go vet -tags=ebpf ./...`
Expected: no output (clean) — confirms `cmd/ebpfselftest` is buildable in both lanes.

Run: `make ebpf-selftest`
Expected: success — prints `built bin/ebpf-selftest — run as root: sudo ./bin/ebpf-selftest`.

- [ ] **Step 4: Commit**

```bash
git add cmd/ebpfselftest/main.go cmd/ebpfselftest/stub.go Makefile
git commit -m "feat: add ebpf-selftest diagnostic tool"
```

---

## Task 10: Final verification and docs

- [ ] **Step 1: Update `CLAUDE.md` — eBPF programs listing**

In `CLAUDE.md`, find:

```
│   ├── bpf/                       eBPF programs + loader (build tag `ebpf`)
│   │   ├── programs/              .bpf.c sources, compiled by `make gen`
│   │   │   ├── syscalls.bpf.c     raw_syscalls/sys_{enter,exit}
```

Replace with:

```
│   ├── bpf/                       eBPF programs + loader (build tag `ebpf`)
│   │   ├── programs/              .bpf.c sources, compiled by `make gen`
│   │   │   ├── target.bpf.h       shared pid-namespace target filter
│   │   │   ├── syscalls.bpf.c     raw_syscalls/sys_{enter,exit}
```

- [ ] **Step 2: Update `CLAUDE.md` — loader listing**

In `CLAUDE.md`, find:

```
│   │   ├── available.go           runtime feature flag (build-tag based)
│   │   ├── caps.go                CAP_BPF / CAP_PERFMON detection
```

Replace with:

```
│   │   ├── available.go           runtime feature flag (build-tag based)
│   │   ├── target.go              pid-namespace target resolver (shared)
│   │   ├── caps.go                CAP_BPF / CAP_PERFMON detection
```

- [ ] **Step 3: Update `CLAUDE.md` — cmd listing**

In `CLAUDE.md`, find:

```
├── cmd/ptop/main.go               entrypoint: parse flags, start model
```

Replace with:

```
├── cmd/ptop/main.go               entrypoint: parse flags, start model
├── cmd/ebpfselftest/              root-only eBPF self-diagnostic
```

- [ ] **Step 4: Document the namespace requirement in `CLAUDE.md`**

In `CLAUDE.md`, find:

```
## Build tags

- `//go:build linux && ebpf` — real eBPF code (loader + program objects)
- `//go:build !linux || !ebpf` — stubs that fail `Start` cleanly
```

Replace with:

```
## PID namespaces

eBPF programs filter the target process via `bpf_get_ns_current_pid_tgid()`,
resolving pids inside the target's PID namespace (dev+inode of
`/proc/<pid>/ns/pid`, written by the Go loader into `struct target_filter`).
This is required because `bpf_get_current_pid_tgid()` returns root-namespace
pids — wrong when ptop runs inside a nested namespace (WSL2, Docker, LXC).
The shared logic lives in `programs/target.bpf.h` and `bpf/target.go`; never
filter with the bare `bpf_get_current_pid_tgid()` again. Verify with
`make ebpf-selftest` → `sudo ./bin/ebpf-selftest`.

## Build tags

- `//go:build linux && ebpf` — real eBPF code (loader + program objects)
- `//go:build !linux || !ebpf` — stubs that fail `Start` cleanly
```

- [ ] **Step 5: Full clean rebuild — both lanes**

Run: `make clean && make gen`
Expected: success — all 7 `.bpf.c` compile.

Run: `go build -o /tmp/ptop ./cmd/ptop && go vet ./... && go test -race -count=1 ./...`
Expected: default lane — build success, vet clean, all tests PASS.

Run: `go build -tags=ebpf -o /tmp/ptop-ebpf ./cmd/ptop && go vet -tags=ebpf ./... && go test -race -count=1 -tags=ebpf ./...`
Expected: eBPF lane — build success, vet clean, all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: document the eBPF pid-namespace filter"
```

- [ ] **Step 7: Hand off for root verification**

Build the binary and the self-test for the user:

Run: `make build-ebpf && make ebpf-selftest`
Expected: `bin/ptop` and `bin/ebpf-selftest` produced.

Tell the user to run, on **WSL2** and on a **native Linux host**:

1. `sudo ./bin/ebpf-selftest` — expect `eBPF self-test PASSED`.
2. `sudo ./bin/ptop --pid <PID>` of a busy process — expect F1 to show real
   CPU %, F2 to populate syscalls, F4 to show per-thread CPU % and context
   switches, and the `?` overlay to show `real via eBPF` for cpu, syscalls,
   io-files, network, memory, locks and threads.

Do not claim the fix works on either platform until the user confirms these
runs.

---

## Self-Review

**Spec coverage:**
- Shared C header + Go resolver (spec §4) → Tasks 1, 2.
- Six uniform collectors (spec §5) → Tasks 2 (cpu), 3, 4, 5, 6, 7.
- Threads collector (spec §6) → Task 8.
- Non-regression on native Linux (spec §7) → both-lane vet/test/build in every
  task; explicit default-lane checks in Tasks 8, 9, 10; `target_test.go` (CI).
- Error handling (spec §8) → `resolveTarget` error path wired through every
  loader; `target_test.go` covers the missing-pid and struct-size cases.
- Testing & verification (spec §9) → Task 1 unit tests; per-task `make gen` +
  both-lane checks; Task 10 root-run handoff.
- ebpf-selftest tool (spec §10) → Task 9.
- Out of scope (spec §2): `model.go` CPU fallback hardening — not touched, as
  intended.

**Placeholder scan:** none — every step has concrete code or exact commands.
`<PID>` in Task 10 Step 7 is a literal the user substitutes.

**Type consistency:** `targetFilter` (Go, Task 1) ↔ `struct target_filter`
(C, Task 2) — both 24 bytes, asserted by `TestTargetFilterSize`.
`resolveTarget`/`writeTargetFilter` defined in Task 1, used identically in
Tasks 2–8. `pid_is_target`/`pid_target_ns` defined in Task 2's header, used in
Tasks 2–8. `PruneDeadTIDs` defined in Task 8 (`threads.go` + stub), called in
Task 8 (`threads_ebpf.go`). No mismatches.
