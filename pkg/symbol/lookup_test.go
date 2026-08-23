package symbol

import (
	"debug/elf"
	"os"
	"testing"
)

// openFixtureModule builds the Go fixture and parses it as a Module.
func openFixtureModule(t *testing.T, ldflags string) (*Module, string) {
	t.Helper()
	path := buildGoFixture(t, ldflags)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	m, err := OpenModule(f, path)
	if err != nil {
		t.Fatalf("OpenModule: %v", err)
	}
	return m, path
}

func TestIsGo(t *testing.T) {
	m, _ := openFixtureModule(t, "")
	if !m.IsGo() {
		t.Error("IsGo = false for a Go binary")
	}

	// A module with no line table is the non-Go case (a C library, or an ELF
	// we failed to find .gopclntab in).
	if (&Module{name: "libc.so.6"}).IsGo() {
		t.Error("IsGo = true for a module with no line table")
	}
}

// A stripped build is the one that matters: -ldflags="-s -w" is the norm for a
// release binary, it removes .symtab entirely, and if the lookup did not fall
// back to .gopclntab the Go allocation probe would only ever attach to debug
// builds.
func TestIsGoSurvivesStripping(t *testing.T) {
	m, _ := openFixtureModule(t, "-s -w")
	if !m.IsGo() {
		t.Error("IsGo = false for a stripped Go binary (.gopclntab should survive -s -w)")
	}
}

func TestFuncStartFromSymbolTable(t *testing.T) {
	m, path := openFixtureModule(t, "")
	want := symValue(t, path, "main.leakyAlloc")

	got, size, ok := m.FuncStart("main.leakyAlloc")
	if !ok {
		t.Fatal("FuncStart(main.leakyAlloc) not found")
	}
	if got != want {
		t.Errorf("FuncStart = %#x, want %#x", got, want)
	}
	if size == 0 {
		t.Error("FuncStart size = 0, want the symbol's extent from .symtab")
	}
}

func TestFuncStartFallsBackToLineTable(t *testing.T) {
	m, path := openFixtureModule(t, "-s -w")

	// Precondition: the fallback is only under test if .symtab is really gone.
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Symbols(); err == nil {
		t.Skip("toolchain kept .symtab under -s -w; nothing to fall back from")
	}

	addr, _, ok := m.FuncStart("main.leakyAlloc")
	if !ok {
		t.Fatal("FuncStart(main.leakyAlloc) not found on a stripped binary")
	}
	// Cross-check against the other direction: the address must resolve back
	// to the function we asked for.
	if fr := m.Resolve(addr); fr.Func != "main.leakyAlloc" {
		t.Errorf("FuncStart(%#x) resolves back to %q, want main.leakyAlloc", addr, fr.Func)
	}
}

// runtime.mallocgc is the actual attach point of the Go allocation probe. If
// this stops resolving on a supported toolchain, the axis goes dark — so it is
// asserted by name rather than left implicit in the fixture's own functions.
func TestFuncStartFindsMallocgc(t *testing.T) {
	for _, ldflags := range []string{"", "-s -w"} {
		name := "plain"
		if ldflags != "" {
			name = "stripped"
		}
		t.Run(name, func(t *testing.T) {
			m, _ := openFixtureModule(t, ldflags)
			addr, _, ok := m.FuncStart("runtime.mallocgc")
			if !ok {
				t.Fatal("FuncStart(runtime.mallocgc) not found")
			}
			if addr == 0 {
				t.Error("runtime.mallocgc resolved to address 0")
			}
			if _, ok := m.FileOffset(addr); !ok {
				t.Error("runtime.mallocgc is in no file-backed segment")
			}
		})
	}
}

func TestFuncStartMissingSymbol(t *testing.T) {
	m, _ := openFixtureModule(t, "")
	if _, _, ok := m.FuncStart("main.thisDoesNotExist"); ok {
		t.Error("FuncStart reported a symbol that is not there")
	}
}

// FileOffset must agree with the ELF program headers, because a uprobe is
// registered by file offset — an off-by-one segment here attaches the probe to
// whatever unrelated instruction lives at that offset.
func TestFileOffsetMatchesProgramHeaders(t *testing.T) {
	m, path := openFixtureModule(t, "")
	addr := symValue(t, path, "main.leakyAlloc")

	got, ok := m.FileOffset(addr)
	if !ok {
		t.Fatal("FileOffset not found for a function address")
	}

	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var want uint64
	var found bool
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		if addr >= p.Vaddr && addr < p.Vaddr+p.Filesz {
			want, found = addr-p.Vaddr+p.Off, true
			break
		}
	}
	if !found {
		t.Fatal("test setup: function address in no PT_LOAD segment")
	}
	if got != want {
		t.Errorf("FileOffset = %#x, want %#x", got, want)
	}

	// Independent check: the bytes at that offset are the function's first
	// instruction, i.e. reading the file there lands inside .text.
	if sec := f.Section(".text"); sec != nil {
		if got < sec.Offset || got >= sec.Offset+sec.Size {
			t.Errorf("FileOffset %#x is outside .text [%#x,%#x)", got, sec.Offset, sec.Offset+sec.Size)
		}
	}
}

func TestFileOffsetRejectsUnmappedAddress(t *testing.T) {
	m := &Module{loads: []progLoad{{off: 0x1000, vaddr: 0x400000, filesz: 0x2000}}}
	if _, ok := m.FileOffset(0x500000); ok {
		t.Error("FileOffset accepted an address in no segment")
	}
	// Past filesz but within a hypothetical memsz (.bss): no file bytes back
	// it, so there is no offset to give.
	if _, ok := m.FileOffset(0x402000); ok {
		t.Error("FileOffset accepted an address past the segment's file content")
	}
}
