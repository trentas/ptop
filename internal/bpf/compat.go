package bpf

import "debug/elf"

// compatExecutable reports whether path is a 32-bit ELF executable.
//
// The io program matches syscalls by number against the 64-bit native table
// (<asm/unistd.h>, #159), and a compat task numbers its syscalls from another
// one: on x86_64 its exit(1) would read as write and its fork(2) as open. The
// per-syscall events the program used before skipped compat tasks entirely, so
// the axis was blind to one; matching by number would make it wrong instead,
// and blind is the honest of the two.
//
// A file that cannot be read or parsed is not reported as compat: the check
// guards against one known wrong answer, it is not a precondition for
// attaching.
//
// Build-tag-free so the default lane tests it.
func compatExecutable(path string) bool {
	f, err := elf.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	return f.Class == elf.ELFCLASS32
}
