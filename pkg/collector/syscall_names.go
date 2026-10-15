package collector

import (
	"sort"
	"strconv"
)

//go:generate go run ../../internal/syscalltbl/gen.go

// syscallTable returns the number → name table for a binary built for goarch,
// or nil for an architecture without one.
//
// The binary's own GOARCH is the right key: the eBPF objects are per
// architecture (#123), so the lane that reports syscall numbers only ever runs
// on a kernel of the architecture it was built for. What it reports is the
// 64-bit native number; a 32-bit (compat) target's numbers come from another
// table and are not translated.
//
// The tables are generated from the kernel's own syscall.tbl files
// (syscall_names_gen.go, internal/syscalltbl). They used to be a hand-curated
// list of the ~50 syscalls expected to dominate a top-N, and the most frequent
// syscall of a real Go process — epoll_pwait — was not on it (#139).
func syscallTable(goarch string) []string {
	switch goarch {
	case "amd64":
		return syscallsAMD64[:]
	case "arm64":
		return syscallsARM64[:]
	}
	return nil
}

// syscallName resolves a syscall number through table, falling back to
// "syscall_<id>" for a number the table does not assign.
func syscallName(id uint32, table []string) string {
	if uint64(id) < uint64(len(table)) && table[id] != "" {
		return table[id]
	}
	return "syscall_" + strconv.FormatUint(uint64(id), 10)
}

// sortSyscallRows orders a snapshot busiest first, ties by name, so the order
// is stable from one snapshot to the next.
func sortSyscallRows(rows []SyscallEvent) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Name < rows[j].Name
	})
}
