package symbol

import (
	"bufio"
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildCFixture compiles testdata/cfixture with the host C compiler and
// returns the ELF path. Skips when no compiler is available — the DWARF path
// is Linux/C tooling, and a machine without cc simply cannot exercise it.
func buildCFixture(t *testing.T, extraFlags ...string) string {
	t.Helper()
	cc := ""
	for _, cand := range []string{"cc", "clang", "gcc"} {
		if p, err := exec.LookPath(cand); err == nil {
			cc = p
			break
		}
	}
	if cc == "" {
		t.Skip("no C compiler on PATH; DWARF fixture cannot be built")
	}
	out := filepath.Join(t.TempDir(), "cfixture")
	args := append([]string{"-O0", "-o", out}, extraFlags...)
	args = append(args, "testdata/cfixture/main.c")
	if o, err := exec.Command(cc, args...).CombinedOutput(); err != nil {
		t.Skipf("compile fixture with %s: %v\n%s", cc, err, o)
	}
	return out
}

// fixtureLine finds the 1-based line number of the source line carrying the
// given marker comment, so the expected value tracks the file instead of being
// a constant that silently rots when the fixture is edited.
func fixtureLine(t *testing.T, marker string) int {
	t.Helper()
	f, err := os.Open("testdata/cfixture/main.c")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		if strings.Contains(sc.Text(), "LINE:"+marker) {
			return n
		}
	}
	t.Fatalf("marker %q not found in the fixture", marker)
	return 0
}

func openCModule(t *testing.T, path string) *Module {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	m, err := OpenModule(f, path)
	if err != nil {
		t.Fatalf("OpenModule: %v", err)
	}
	return m
}

// The gap this closes: before DWARF, a C frame resolved to a function name and
// nothing else, so a delta could say which function moved but never which
// line — and a line is what crosses against a code diff.
func TestResolveCGivesFileAndLine(t *testing.T) {
	path := buildCFixture(t, "-g")
	m := openCModule(t, path)

	for _, c := range []struct{ fn, marker string }{
		{"alloc_small", "alloc_small_body"},
		{"alloc_big", "alloc_big_body"},
	} {
		t.Run(c.fn, func(t *testing.T) {
			// Resolve the address of the malloc call inside the function, not
			// the function entry: the entry maps to the declaration line,
			// while the body line is the one a call site actually reports.
			addr := symValue(t, path, c.fn)
			var fr Frame
			// Walk forward a little to land inside the body. The prologue is a
			// handful of instructions; 64 bytes covers it on both arm64 and
			// x86-64 at -O0.
			wantLine := fixtureLine(t, c.marker)
			for off := uint64(0); off <= 64; off += 4 {
				got := m.Resolve(addr + off)
				if got.Line == wantLine {
					fr = got
					break
				}
				if fr.Func == "" {
					fr = got
				}
			}
			if fr.Func != c.fn {
				t.Errorf("Func = %q, want %q", fr.Func, c.fn)
			}
			if !strings.HasSuffix(fr.File, "main.c") {
				t.Errorf("File = %q, want …/main.c", fr.File)
			}
			if fr.Line != wantLine {
				t.Errorf("Line = %d, want %d (the malloc call in %s)", fr.Line, wantLine, c.fn)
			}
		})
	}
}

// Without -g there is no debug info at all. The module must still resolve the
// function name from .symtab and simply leave file:line empty — the behaviour
// that shipped before DWARF, which most production binaries still get.
func TestResolveCWithoutDebugInfoKeepsFuncOnly(t *testing.T) {
	path := buildCFixture(t)
	m := openCModule(t, path)

	if m.dwarfSecs != nil {
		t.Skip("compiler emitted debug info without -g; nothing to test here")
	}
	fr := m.Resolve(symValue(t, path, "alloc_small"))
	if fr.Func != "alloc_small" {
		t.Errorf("Func = %q, want alloc_small", fr.Func)
	}
	if fr.File != "" || fr.Line != 0 {
		t.Errorf("file:line = %q:%d, want empty without debug info", fr.File, fr.Line)
	}
}

// A Go binary must keep taking the .gopclntab path: it is compact, always
// present, and authoritative. DWARF must not shadow it — a Go build with
// debug info would otherwise get its file:line from the slower source.
func TestGoModuleStillPrefersLineTable(t *testing.T) {
	path := buildGoFixture(t, "")
	m := openCModule(t, path)
	fr := m.Resolve(symValue(t, path, "main.leakyAlloc"))
	if fr.Func != "main.leakyAlloc" {
		t.Errorf("Func = %q, want main.leakyAlloc", fr.Func)
	}
	// gosym's answer, canonicalized to the import path (#107). DWARF's would
	// still be the build machine's absolute path, so this also says which
	// source answered.
	if fr.File != "main.go" {
		t.Errorf("File = %q, want main.go (gosym, canonicalized)", fr.File)
	}
}

// The address is outside every compile unit: the lookup must decline rather
// than return the nearest line it happened to find.
func TestDwarfLineRejectsUnknownPC(t *testing.T) {
	m := openCModule(t, buildCFixture(t, "-g"))
	if _, _, ok := m.dwarfLine(0xdeadbeef0000); ok {
		t.Error("dwarfLine resolved an address in no compile unit")
	}
}

func TestDwarfLineOnModuleWithoutSections(t *testing.T) {
	m := &Module{name: "stripped.so"}
	if _, _, ok := m.dwarfLine(0x1000); ok {
		t.Error("dwarfLine resolved on a module with no debug sections")
	}
}

// loadDWARFSections must decline an image whose debug info would blow the
// budget, and must not half-load one that is missing the line program.
func TestLoadDWARFSectionsRequiresInfoAndLine(t *testing.T) {
	path := buildCFixture(t, "-g")
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if secs := loadDWARFSections(f); secs == nil {
		t.Fatal("loadDWARFSections declined a -g binary")
	} else if secs[".debug_info"] == nil || secs[".debug_line"] == nil {
		t.Error("loaded sections missing .debug_info or .debug_line")
	}
}
