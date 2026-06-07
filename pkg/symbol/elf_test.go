package symbol

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseBuildIDNote(t *testing.T) {
	bo := binary.LittleEndian
	var b []byte
	u32 := func(v uint32) {
		var x [4]byte
		bo.PutUint32(x[:], v)
		b = append(b, x[:]...)
	}
	desc := []byte{0xde, 0xad, 0xbe, 0xef}
	u32(4)                 // namesz: "GNU\0"
	u32(uint32(len(desc))) // descsz
	u32(3)                 // NT_GNU_BUILD_ID
	b = append(b, "GNU\x00"...)
	b = append(b, desc...)

	if got := parseBuildIDNote(b, bo); got != "deadbeef" {
		t.Errorf("parseBuildIDNote = %q, want deadbeef", got)
	}
	if got := parseBuildIDNote([]byte{0, 0, 0, 0}, bo); got != "" {
		t.Errorf("no-note = %q, want empty", got)
	}
}

func TestFileVaddr(t *testing.T) {
	cases := []struct {
		name                       string
		loads                      []progLoad
		addr, segStart, segFileOff uint64
		want                       uint64
		ok                         bool
	}{
		// ET_EXEC: text mapped at its link vaddr 0x401000 from file off 0x1000.
		{"non-pie", []progLoad{{off: 0x1000, vaddr: 0x401000, filesz: 0x2000}},
			0x401234, 0x401000, 0x1000, 0x401234, true},
		// PIE/ET_DYN: link vaddr small (0x1000), mapped high under ASLR.
		{"pie", []progLoad{{off: 0x1000, vaddr: 0x1000, filesz: 0x2000}},
			0x7f0000000234, 0x7f0000000000, 0x1000, 0x1234, true},
		// addr's file offset falls outside every PT_LOAD.
		{"out-of-load", []progLoad{{off: 0x1000, vaddr: 0x1000, filesz: 0x2000}},
			0xdead0000, 0xdead0000, 0x9000, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := fileVaddr(c.addr, c.segStart, c.segFileOff, c.loads)
			if ok != c.ok || (ok && got != c.want) {
				t.Errorf("fileVaddr = %#x,%v want %#x,%v", got, ok, c.want, c.ok)
			}
		})
	}
}

func TestLookupFunc(t *testing.T) {
	funcs := []funcSym{
		{value: 0x1000, size: 0x100, name: "a"},
		{value: 0x1200, size: 0, name: "b"}, // size-0 asm stub
		{value: 0x1400, size: 0x50, name: "c"},
	}
	cases := []struct {
		addr uint64
		want string
		ok   bool
	}{
		{0x0fff, "", false}, // before first symbol
		{0x1000, "a", true}, // start of a
		{0x10ff, "a", true}, // within sized a
		{0x1100, "", false}, // gap after sized a
		{0x1200, "b", true}, // size-0 b
		{0x13ff, "b", true}, // size-0 b extends to next symbol
		{0x1400, "c", true},
		{0x1500, "", false}, // gap after sized c
	}
	for _, c := range cases {
		got, ok := lookupFunc(funcs, c.addr)
		if ok != c.ok || got != c.want {
			t.Errorf("lookupFunc(%#x) = %q,%v want %q,%v", c.addr, got, ok, c.want, c.ok)
		}
	}
}

func TestResolveStrippedFallback(t *testing.T) {
	// No symbols, no gosym → module + module-relative offset.
	m := &Module{name: "libfoo.so", loadBase: 0x1000, buildID: "abcd"}
	fr := m.Resolve(0x2500)
	if fr.Func != "" || fr.Module != "libfoo.so" || fr.Offset != 0x1500 || fr.BuildID != "abcd" {
		t.Errorf("fallback frame = %+v", fr)
	}
}

// buildGoFixture cross-compiles testdata/gofixture for linux/amd64 (pure Go,
// CGO off → builds on any host including macOS) and returns the ELF path.
func buildGoFixture(t *testing.T, ldflags string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "fixture")
	args := []string{"build", "-o", out}
	if ldflags != "" {
		args = append(args, "-ldflags", ldflags)
	}
	args = append(args, "./testdata/gofixture")
	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fixture: %v\n%s", err, out)
	}
	return out
}

func symValue(t *testing.T, path, name string) uint64 {
	t.Helper()
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("elf.Open: %v", err)
	}
	defer f.Close()
	syms, err := f.Symbols()
	if err != nil {
		t.Fatalf("Symbols: %v", err)
	}
	for _, s := range syms {
		if s.Name == name {
			return s.Value
		}
	}
	t.Fatalf("symbol %q not found", name)
	return 0
}

func TestModuleResolveGo(t *testing.T) {
	path := buildGoFixture(t, "-B 0x0011223344556677")
	addr := symValue(t, path, "main.leakyAlloc")

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m, err := OpenModule(f, path)
	if err != nil {
		t.Fatalf("OpenModule: %v", err)
	}

	fr := m.Resolve(addr)
	if fr.Func != "main.leakyAlloc" {
		t.Errorf("Func = %q, want main.leakyAlloc", fr.Func)
	}
	if !strings.HasSuffix(fr.File, "gofixture/main.go") {
		t.Errorf("File = %q, want …/gofixture/main.go", fr.File)
	}
	if fr.Line <= 0 {
		t.Errorf("Line = %d, want > 0", fr.Line)
	}
	if fr.BuildID != "0011223344556677" {
		t.Errorf("BuildID = %q, want 0011223344556677", fr.BuildID)
	}
}

func TestModuleResolveStrippedGo(t *testing.T) {
	// -s strips .symtab but .gopclntab survives → gosym still resolves.
	path := buildGoFixture(t, "-s -w")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m, err := OpenModule(f, path)
	if err != nil {
		t.Fatalf("OpenModule: %v", err)
	}
	tab := m.gosym()
	if tab == nil {
		t.Fatal("gosym nil on stripped Go binary (.gopclntab should survive -s)")
	}
	fn := tab.LookupFunc("main.leakyAlloc")
	if fn == nil {
		t.Fatal("LookupFunc(main.leakyAlloc) = nil")
	}
	fr := m.Resolve(fn.Entry)
	if fr.Func != "main.leakyAlloc" || !strings.HasSuffix(fr.File, "gofixture/main.go") {
		t.Errorf("stripped resolve = %+v", fr)
	}
}
