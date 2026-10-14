package symbol

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
	"unsafe"
)

// mappingSupported is where OpenModule maps sections (mmap_unix.go). On those
// platforms a Module without a mapping is a regression, not a skip.
var mappingSupported = runtime.GOOS == "linux" || runtime.GOOS == "darwin"

func requireMapping(t *testing.T, m *Module) {
	t.Helper()
	if !mappingSupported {
		t.Skip("sections are not mapped on this platform")
	}
	if m.mapping == nil {
		t.Fatal("Module opened from a file has no mapping")
	}
}

// copyExecutable copies src to a new file — a new inode — at dst.
func copyExecutable(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o755); err != nil {
		t.Fatal(err)
	}
}

func openModuleAt(t *testing.T, path, name string) *Module {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m, err := OpenModule(f, name)
	if err != nil {
		t.Fatalf("OpenModule(%s): %v", path, err)
	}
	return m
}

// The case #137 is about: the same executable opened by several callers, under
// different names. One parse between them, and each keeps its own name — a
// Frame must not say "exe" because /proc/<pid>/exe happened to open it first.
func TestModulesOnOneFileShareAnImage(t *testing.T) {
	path := buildGoFixture(t, "")
	link := filepath.Join(t.TempDir(), "other-name")
	if err := os.Link(path, link); err != nil {
		t.Skipf("hard link: %v", err)
	}

	a := openModuleAt(t, path, "/usr/bin/app")
	b := openModuleAt(t, link, "/proc/1/exe")
	if a.image != b.image {
		t.Fatal("two Modules on one file parsed it twice")
	}

	addr := symValue(t, path, "main.leakyAlloc")
	fa, fb := a.Resolve(addr), b.Resolve(addr)
	if fa.Module != "app" || fb.Module != "exe" {
		t.Errorf("Frame.Module = %q, %q; want each Module's own name (app, exe)", fa.Module, fb.Module)
	}
	fa.Module, fb.Module = "", ""
	if fa != fb || fa.Func != "main.leakyAlloc" {
		t.Errorf("frames differ beyond the name: %+v vs %+v", fa, fb)
	}
}

// A copy has the same bytes but is a different file. It is not shared, which
// is what keeps the key honest: identity, not a guess about contents.
func TestCopiedFileIsParsedSeparately(t *testing.T) {
	path := buildGoFixture(t, "")
	cp := filepath.Join(t.TempDir(), "copy")
	copyExecutable(t, path, cp)

	if openModuleAt(t, path, path).image == openModuleAt(t, cp, cp).image {
		t.Error("a copy of the file shared the original's image")
	}
}

// A file rewritten in place keeps its inode. Its size or mtime moves, and so
// must the key — otherwise the cache serves the old binary's symbols for the
// new one.
func TestRewrittenFileIsNotServedStale(t *testing.T) {
	src := buildGoFixture(t, "")
	path := filepath.Join(t.TempDir(), "app")
	copyExecutable(t, src, path)
	before := openModuleAt(t, path, path)

	other := buildGoFixture(t, "-s -w") // a different, smaller image
	b, err := os.ReadFile(other)
	if err != nil {
		t.Fatal(err)
	}
	// Truncate and rewrite: same inode, new contents.
	if err := os.WriteFile(path, b, 0o755); err != nil {
		t.Fatal(err)
	}
	after := openModuleAt(t, path, path)
	if after.image == before.image {
		t.Fatal("rewritten file was served the old image")
	}
	if len(after.funcs) != 0 {
		t.Errorf("rewritten (stripped) image has %d symbols; it is the old file's parse", len(after.funcs))
	}
}

// The symbolizing collectors of one target reach their first frame in the same
// publish tick. They must wait on one parse, not run one each — concurrent
// parses are the transient peak.
func TestConcurrentOpensParseOnce(t *testing.T) {
	path := buildGoFixture(t, "")
	const n = 8
	mods := make([]*Module, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, err := os.Open(path)
			if err != nil {
				t.Error(err)
				return
			}
			defer f.Close()
			m, err := OpenModule(f, path)
			if err != nil {
				t.Error(err)
				return
			}
			_ = m.Resolve(0) // builds the line table, concurrently with the others
			mods[i] = m
		}()
	}
	wg.Wait()
	for i, m := range mods {
		if m == nil || m.image != mods[0].image {
			t.Fatalf("Module %d did not share the first one's image", i)
		}
	}
}

// The cache must not be what keeps a parse alive. A server that has watched
// many short-lived targets (#72) should hold nothing for the ones that are
// gone, and the mapping should go with them.
func TestImageReleasedWithLastModule(t *testing.T) {
	path := buildGoFixture(t, "")
	key := openAndForget(t, path)

	deadline := time.Now().Add(5 * time.Second)
	for cached(key) {
		if time.Now().After(deadline) {
			t.Fatal("image still cached after its last Module became unreachable")
		}
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
}

func openAndForget(t *testing.T, path string) fileKey {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	key, ok := identify(f)
	if !ok {
		if mappingSupported {
			t.Fatal("no file identity on a platform that has one")
		}
		t.Skip("file identity is not available on this platform")
	}
	if _, err := OpenModule(f, path); err != nil {
		t.Fatal(err)
	}
	if !cached(key) {
		t.Fatal("OpenModule on a file did not cache its image")
	}
	return key
}

func cached(key fileKey) bool {
	images.mu.Lock()
	defer images.mu.Unlock()
	_, ok := images.slots[key]
	return ok
}

// The structural half of #137: the line table is a window onto the file, not a
// copy of it. Checked by address, because a test that only resolves frames
// passes just as well against a heap copy.
func TestGoLineTableIsMappedNotCopied(t *testing.T) {
	m := openModuleAt(t, buildGoFixture(t, "-s -w"), "app")
	requireMapping(t, m)
	if len(m.pclnData) == 0 {
		t.Fatal("fixture has no .gopclntab")
	}
	if !within(m.pclnData, m.mapping) {
		t.Error(".gopclntab is a heap copy, not a slice of the mapping")
	}
	if fr := m.Resolve(mustFuncStart(t, m, "main.leakyAlloc")); fr.Func != "main.leakyAlloc" {
		t.Errorf("resolve through the mapping = %+v", fr)
	}
}

func mustFuncStart(t *testing.T, m *Module, name string) uint64 {
	t.Helper()
	v, _, ok := m.FuncStart(name)
	if !ok {
		t.Fatalf("FuncStart(%s) not found", name)
	}
	return v
}

func within(sub, all []byte) bool {
	s := uintptr(unsafe.Pointer(unsafe.SliceData(sub)))
	a := uintptr(unsafe.Pointer(unsafe.SliceData(all)))
	return s >= a && s+uintptr(len(sub)) <= a+uintptr(len(all))
}

// A mapping is only as good as the file under it. Truncated while mapped, the
// next read past the new end is a SIGBUS — which the runtime turns into a dead
// process unless the read is guarded. A lookup must degrade instead, whether
// the line table was built before the truncation or is built after it.
func TestTruncatedFileDegradesInsteadOfCrashing(t *testing.T) {
	src := buildGoFixture(t, "-s -w")
	for _, warm := range []bool{false, true} {
		name := map[bool]string{false: "table-built-after", true: "table-built-before"}[warm]
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "app")
			copyExecutable(t, src, path)
			m := openModuleAt(t, path, path)
			requireMapping(t, m)
			addr := uint64(0)
			if warm {
				addr = mustFuncStart(t, m, "main.leakyAlloc")
			}
			if err := os.Truncate(path, 0); err != nil {
				t.Fatal(err)
			}

			fr := m.Resolve(addr + 1)
			if fr.Module != "app" {
				t.Errorf("degraded frame lost its module: %+v", fr)
			}
			_, _, _ = m.FuncStart("main.main")
		})
	}
}

// Anything that is not a file keeps the old contract: parsed privately, into
// heap copies, never cached — there is no identity to share it by.
func TestReaderAtIsParsedPrivately(t *testing.T) {
	b, err := os.ReadFile(buildGoFixture(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	m1, err := OpenModule(bytes.NewReader(b), "a")
	if err != nil {
		t.Fatal(err)
	}
	m2, err := OpenModule(bytes.NewReader(b), "b")
	if err != nil {
		t.Fatal(err)
	}
	if m1.image == m2.image {
		t.Error("two ReaderAt opens shared an image")
	}
	if m1.mapping != nil {
		t.Error("a ReaderAt open produced a mapping")
	}
	if !m1.IsGo() {
		t.Error("ReaderAt open lost the line table")
	}
}

func TestFileBuildIDReadsOnlyTheNote(t *testing.T) {
	f, err := os.Open(buildGoFixture(t, "-B 0x0011223344556677"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if got := fileBuildID(f); got != "0011223344556677" {
		t.Errorf("fileBuildID = %q, want 0011223344556677", got)
	}
	if got := fileBuildID(bytes.NewReader([]byte("not an ELF"))); got != "" {
		t.Errorf("fileBuildID(garbage) = %q, want empty", got)
	}
}
