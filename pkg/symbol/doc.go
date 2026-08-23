// Package symbol resolves runtime stack addresses captured by ptop's eBPF
// tracers into human-readable frames (function + file:line). It is the
// userspace half of issue #54.
//
// The ELF Module core (elf.go) is OS-agnostic: it parses any ELF image with
// debug/elf and debug/gosym, so it works — and is unit-tested — on every
// platform. The Symbolizer (proc_linux.go) ties a per-module cache to a live
// process via /proc/<pid>/maps and is Linux-only (proc_other.go stubs it).
//
// Per-module resolution order: the Go line table (.gopclntab) yields func +
// file:line for Go binaries and survives symbol stripping; the ELF symbol
// table (.symtab/.dynsym) yields function names for C/C++, and DWARF line info
// (dwarf.go) fills in their file:line where the image carries debug sections;
// a stripped module degrades gracefully to "module+0xoffset". Modules are
// parsed once and cached.
//
// Name → address lookup (lookup.go) is the inverse direction, used to place a
// uprobe on a named function such as runtime.mallocgc.
//
// Deferred (see #54): C++ demangling, and kernel-stack resolution via
// /proc/kallsyms.
package symbol
