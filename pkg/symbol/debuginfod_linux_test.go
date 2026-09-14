//go:build linux

package symbol

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The end-to-end shape of #119, built the way the ecosystem actually publishes
// symbols: one image compiled with debug info, then split by objcopy into the
// stripped binary that ships and the separate debug file that goes to a symbol
// store. Both carry the same build-id, which is the only thing tying them
// together once the binary is on someone else's machine.
//
// It is Linux-only because it symbolizes through a live Symbolizer, and the
// objcopy recipe is also what exercises the SHT_NOBITS handling: a separate
// debug image keeps every allocated section's header with nothing behind it.
func TestSymbolizeStrippedModuleFromStore(t *testing.T) {
	const buildID = "00112233445566778899aabbccddeeff00112233"
	objcopy := lookTool(t, "objcopy")

	full := buildCFixture(t, "-g", "-Wl,--build-id=0x"+buildID)
	dir := filepath.Dir(full)
	debugImage := filepath.Join(dir, "cfixture.debug")
	stripped := filepath.Join(dir, "cfixture.stripped")

	run(t, objcopy, "--only-keep-debug", full, debugImage)
	run(t, objcopy, "--strip-all", full, stripped)

	// Precondition: the shipped binary really cannot name anything on its own.
	// Without this the test would pass even if the store were never consulted.
	local := openCModule(t, stripped)
	addr := symValue(t, full, "alloc_small")
	if fr := local.Resolve(addr); fr.Func != "" {
		t.Fatalf("stripped fixture still resolves %q; the compiler did not strip it", fr.Func)
	}
	if local.BuildID() != buildID {
		t.Fatalf("stripped fixture build-id = %q, want %s", local.BuildID(), buildID)
	}

	store := t.TempDir()
	if err := os.MkdirAll(filepath.Join(store, buildID), 0o755); err != nil {
		t.Fatal(err)
	}
	copyFile(t, debugImage, filepath.Join(store, buildID, debuginfoFile))

	sym := symbolizerOver(t, stripped, local, NewDebuginfod(Options{CacheDir: store}))
	fr := sym.Symbolize(runtimeAddrFor(t, local, addr))

	if fr.Func != "alloc_small" {
		t.Errorf("Func = %q, want alloc_small (from the store)", fr.Func)
	}
	if !strings.HasSuffix(fr.File, "main.c") {
		t.Errorf("File = %q, want …/main.c", fr.File)
	}
	// Identity stays with the mapped image: the debug file is itself named
	// "debuginfo", and reporting that as the module would be a lie.
	if fr.Module != filepath.Base(stripped) {
		t.Errorf("Module = %q, want %q", fr.Module, filepath.Base(stripped))
	}
	if fr.BuildID != buildID {
		t.Errorf("BuildID = %q, want %s", fr.BuildID, buildID)
	}
}

// And with no source configured the same frame stays a bare address — the
// behaviour every run without the flags keeps.
func TestSymbolizeStrippedModuleWithoutASource(t *testing.T) {
	const buildID = "00112233445566778899aabbccddeeff00112233"
	objcopy := lookTool(t, "objcopy")

	full := buildCFixture(t, "-g", "-Wl,--build-id=0x"+buildID)
	stripped := filepath.Join(filepath.Dir(full), "cfixture.stripped")
	run(t, objcopy, "--strip-all", full, stripped)

	local := openCModule(t, stripped)
	addr := symValue(t, full, "alloc_small")
	sym := symbolizerOver(t, stripped, local, nil)

	if fr := sym.Symbolize(runtimeAddrFor(t, local, addr)); fr.Func != "" || fr.File != "" {
		t.Errorf("frame = %+v, want no symbols with no source configured", fr)
	}
}

// symbolizerOver builds a Symbolizer whose single segment maps path identically
// (segment start 0, file offset 0), so a file offset IS a runtime address. That
// is what runtimeAddrFor inverts.
func symbolizerOver(t *testing.T, path string, m *Module, d *Debuginfod) *Symbolizer {
	t.Helper()
	return &Symbolizer{
		pid:        os.Getpid(),
		segs:       []segment{{start: 0, end: ^uint64(0), fileOff: 0, path: path}},
		mods:       map[string]*Module{path: m},
		debuginfod: d,
	}
}

// runtimeAddrFor inverts fileVaddr for the identity mapping above: it returns
// the address Symbolize must be handed for the module's fileVaddr to come back
// out as symAddr.
func runtimeAddrFor(t *testing.T, m *Module, symAddr uint64) uint64 {
	t.Helper()
	for _, p := range m.loads {
		if symAddr >= p.vaddr && symAddr < p.vaddr+p.filesz {
			return symAddr - p.vaddr + p.off
		}
	}
	t.Fatalf("vaddr %#x is in no PT_LOAD of %s", symAddr, m.Name())
	return 0
}

func lookTool(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s not on PATH; the split-debug fixture cannot be built", name)
	}
	return p
}

func run(t *testing.T, tool string, args ...string) {
	t.Helper()
	if out, err := exec.Command(tool, args...).CombinedOutput(); err != nil {
		t.Skipf("%s %v: %v\n%s", tool, args, err, out)
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
