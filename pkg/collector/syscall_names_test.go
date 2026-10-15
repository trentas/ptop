package collector

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestSyscallNamesCoverKernelTables reads the kernel's tables back and requires
// every native 64-bit entry to resolve to its own name (#139).
//
// It parses the .tbl files itself instead of trusting the generator, so a
// generator bug, a hand edit of the generated file, or a table updated without
// regenerating all fail here. Numbers the kernel leaves unassigned — x86_64's
// 337..423, the generic table's arch-specific 244..259 — are not entries and
// stay "syscall_<n>".
func TestSyscallNamesCoverKernelTables(t *testing.T) {
	cases := []struct {
		goarch string
		file   string
		abis   []string
	}{
		{"amd64", "amd64.tbl", []string{"common", "64"}},
		{"arm64", "arm64.tbl", []string{"common", "64", "renameat", "rlimit", "memfd_secret"}},
	}
	for _, c := range cases {
		t.Run(c.goarch, func(t *testing.T) {
			table := syscallTable(c.goarch)
			want := readKernelTable(t, filepath.Join("..", "..", "internal", "syscalltbl", c.file), c.abis)
			if len(want) < 300 {
				t.Fatalf("%s: only %d entries parsed — wrong file or ABI filter?", c.file, len(want))
			}
			for nr, name := range want {
				if got := syscallName(uint32(nr), table); got != name {
					t.Errorf("%s %d = %q, the kernel table says %q", c.goarch, nr, got, name)
				}
			}
			// The other direction: the generated table names nothing the
			// kernel's does not.
			for nr, name := range table {
				if name != "" && want[nr] != name {
					t.Errorf("%s %d = %q, which the kernel table does not list", c.goarch, nr, name)
				}
			}
		})
	}
}

func readKernelTable(t *testing.T, path string, abis []string) map[int]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	keep := make(map[string]bool, len(abis))
	for _, a := range abis {
		keep[a] = true
	}
	out := make(map[int]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 || strings.HasPrefix(fields[0], "#") || !keep[fields[1]] {
			continue
		}
		nr, err := strconv.Atoi(fields[0])
		if err != nil {
			t.Fatalf("%s: %q: %v", path, sc.Text(), err)
		}
		out[nr] = fields[2]
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestSyscallNameSpotChecks pins the names a real capture published as bare
// numbers (#139): an otelcol-contrib on amd64 whose most frequent syscall came
// out "syscall_281".
func TestSyscallNameSpotChecks(t *testing.T) {
	cases := []struct {
		goarch string
		id     uint32
		want   string
	}{
		{"amd64", 281, "epoll_pwait"},
		{"amd64", 434, "pidfd_open"},
		{"amd64", 140, "getpriority"},
		{"amd64", 267, "readlinkat"},
		{"amd64", 204, "sched_getaffinity"},
		{"amd64", 15, "rt_sigreturn"},
		{"amd64", 99, "sysinfo"},
		{"amd64", 202, "futex"},
		{"arm64", 22, "epoll_pwait"},
		{"arm64", 98, "futex"},
		{"arm64", 79, "newfstatat"}, // the 64-bit entry, not stat64's fstatat64
		{"arm64", 163, "getrlimit"}, // an arm64-only ABI column (rlimit)
		// Unassigned numbers and unknown architectures fall back.
		{"amd64", 400, "syscall_400"},
		{"amd64", 0x40000000, "syscall_1073741824"},
		{"arm64", 244, "syscall_244"},
		{"riscv64", 22, "syscall_22"},
	}
	for _, c := range cases {
		if got := syscallName(c.id, syscallTable(c.goarch)); got != c.want {
			t.Errorf("%s %d = %q, want %q", c.goarch, c.id, got, c.want)
		}
	}
}
