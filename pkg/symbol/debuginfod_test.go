package symbol

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

const (
	fixtureBuildID = "0011223344556677"
	otherBuildID   = "aabbccddeeff0011"
)

// serveFixture serves path at the debuginfod route for id, counting requests.
func serveFixture(t *testing.T, id, path string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/buildid/"+id+"/debuginfo" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, path)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func resolvesLeakyAlloc(t *testing.T, m *Module, path string) {
	t.Helper()
	if m == nil {
		t.Fatal("Module = nil, want the fixture")
	}
	fr := m.Resolve(symValue(t, path, "main.leakyAlloc"))
	if fr.Func != "main.leakyAlloc" {
		t.Errorf("Func = %q, want main.leakyAlloc", fr.Func)
	}
}

func TestNormalizeBuildID(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"0011223344556677", "0011223344556677", true},
		{"00AABBCCDDEEFF11", "00aabbccddeeff11", true}, // case-folded
		{"", "", false},
		{"deadbe", "", false},            // shorter than 8
		{"0011223344556678a", "", false}, // odd length
		{"00112233445566zz", "", false},  // not hex
		// The id becomes a path segment and a URL segment, so traversal and
		// separators are rejected outright rather than escaped.
		{"../../etc/passwd", "", false},
		{"0011223344556677/x", "", false},
	}
	for _, c := range cases {
		got, ok := normalizeBuildID(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("normalizeBuildID(%q) = %q,%v want %q,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestDebuginfoURL(t *testing.T) {
	const id = "0011223344556677"
	cases := []struct {
		base, want string
		wantErr    bool
	}{
		{base: "https://debuginfod.example", want: "https://debuginfod.example/buildid/" + id + "/debuginfo"},
		{base: "https://debuginfod.example/", want: "https://debuginfod.example/buildid/" + id + "/debuginfo"},
		{base: "http://host:8002/prefix", want: "http://host:8002/prefix/buildid/" + id + "/debuginfo"},
		{base: "  https://spaced.example  ", want: "https://spaced.example/buildid/" + id + "/debuginfo"},
		{base: "ftp://nope.example", wantErr: true},
		{base: "debuginfod.example", wantErr: true}, // no scheme
		{base: "https://", wantErr: true},           // no host
	}
	for _, c := range cases {
		got, err := debuginfoURL(c.base, id)
		if c.wantErr {
			if err == nil {
				t.Errorf("debuginfoURL(%q) = %q, want error", c.base, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("debuginfoURL(%q) = %q,%v want %q", c.base, got, err, c.want)
		}
	}
}

func TestParseDebuginfodURLs(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"https://a.example", []string{"https://a.example"}},
		// DEBUGINFOD_URLS is space-separated; a flag invites commas.
		{"https://a.example https://b.example", []string{"https://a.example", "https://b.example"}},
		{"https://a.example,https://b.example", []string{"https://a.example", "https://b.example"}},
		{"https://a.example, ,https://b.example", []string{"https://a.example", "https://b.example"}},
	}
	for _, c := range cases {
		got := ParseDebuginfodURLs(c.in)
		if len(got) != len(c.want) {
			t.Errorf("ParseDebuginfodURLs(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("ParseDebuginfodURLs(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

// The zero Options configures nothing, which is what makes "off by default"
// the default rather than something a caller has to remember.
func TestDebuginfodDisabledByDefault(t *testing.T) {
	if (Options{}).Enabled() {
		t.Error("zero Options is Enabled")
	}
	d := NewDebuginfod(Options{})
	if d != nil {
		t.Fatalf("NewDebuginfod(zero) = %v, want nil", d)
	}
	if m := d.Module(fixtureBuildID); m != nil {
		t.Error("nil *Debuginfod resolved a module")
	}
}

// A vendor symbol bundle unpacked into the store resolves with no server
// configured at all — the offline half of #119.
func TestDebuginfodResolvesFromLocalStore(t *testing.T) {
	fixture := buildGoFixture(t, "-B 0x"+fixtureBuildID)
	cache := t.TempDir()
	stageFixture(t, cache, fixtureBuildID, fixture)

	d := NewDebuginfod(Options{CacheDir: cache})
	if d == nil {
		t.Fatal("NewDebuginfod(CacheDir) = nil")
	}
	resolvesLeakyAlloc(t, d.Module(fixtureBuildID), fixture)
}

// The property the whole feature rests on: a file whose own build-id is not the
// one asked for is ABSENCE, never a best guess.
func TestDebuginfodRejectsBuildIDMismatch(t *testing.T) {
	fixture := buildGoFixture(t, "-B 0x"+fixtureBuildID)
	cache := t.TempDir()
	// Right layout, wrong contents — exactly what a mis-published bundle looks
	// like, and what would silently mis-attribute every frame in the module.
	stageFixture(t, cache, otherBuildID, fixture)

	d := NewDebuginfod(Options{CacheDir: cache})
	if m := d.Module(otherBuildID); m != nil {
		t.Fatalf("resolved a module carrying build-id %s for %s", fixtureBuildID, otherBuildID)
	}
}

// An image with no build-id note cannot be tied to the target, so it is refused
// rather than trusted on the strength of its path.
func TestDebuginfodRejectsUnidentifiedImage(t *testing.T) {
	fixture := buildGoFixture(t, "") // no -B: no build-id note
	cache := t.TempDir()
	stageFixture(t, cache, fixtureBuildID, fixture)

	if m := NewDebuginfod(Options{CacheDir: cache}).Module(fixtureBuildID); m != nil {
		t.Fatal("resolved an image with no build-id")
	}
}

func TestDebuginfodFetchesAndCaches(t *testing.T) {
	fixture := buildGoFixture(t, "-B 0x"+fixtureBuildID)
	srv, hits := serveFixture(t, fixtureBuildID, fixture)
	cache := t.TempDir()

	d := NewDebuginfod(Options{URLs: []string{srv.URL}, CacheDir: cache})
	resolvesLeakyAlloc(t, d.Module(fixtureBuildID), fixture)

	// Written into the store, so the next process on this host resolves offline.
	cached := filepath.Join(cache, fixtureBuildID, debuginfoFile)
	if _, err := os.Stat(cached); err != nil {
		t.Fatalf("fetched file not cached at %s: %v", cached, err)
	}
	offline := NewDebuginfod(Options{CacheDir: cache}) // no URLs: no network
	resolvesLeakyAlloc(t, offline.Module(fixtureBuildID), fixture)
	if got := hits.Load(); got != 1 {
		t.Errorf("server hits = %d, want 1 (the offline client must not query)", got)
	}
}

// One lookup per build-id for the life of the process: the hit is remembered,
// and concurrent callers block on the first rather than each downloading.
func TestDebuginfodLooksUpEachBuildIDOnce(t *testing.T) {
	fixture := buildGoFixture(t, "-B 0x"+fixtureBuildID)
	srv, hits := serveFixture(t, fixtureBuildID, fixture)
	d := NewDebuginfod(Options{URLs: []string{srv.URL}, CacheDir: t.TempDir()})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if m := d.Module(fixtureBuildID); m == nil {
				t.Error("Module = nil")
			}
		}()
	}
	wg.Wait()
	if got := hits.Load(); got != 1 {
		t.Errorf("server hits = %d, want 1", got)
	}
}

// A miss is remembered too — a stripped module with no published symbols costs
// one query, not one per frame.
func TestDebuginfodRemembersAMiss(t *testing.T) {
	srv, hits := serveFixture(t, "not-this-one", "")
	d := NewDebuginfod(Options{URLs: []string{srv.URL}, CacheDir: t.TempDir()})

	for i := 0; i < 5; i++ {
		if m := d.Module(fixtureBuildID); m != nil {
			t.Fatal("Module resolved against a 404")
		}
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("server hits = %d, want 1", got)
	}
}

// A server that answers with the wrong image must not leave that image in the
// cache: one bad server would otherwise poison every later run on the host.
func TestDebuginfodDoesNotCacheAMismatch(t *testing.T) {
	fixture := buildGoFixture(t, "-B 0x"+fixtureBuildID)
	srv, _ := serveFixture(t, otherBuildID, fixture) // serves the WRONG image
	cache := t.TempDir()

	d := NewDebuginfod(Options{URLs: []string{srv.URL}, CacheDir: cache})
	if m := d.Module(otherBuildID); m != nil {
		t.Fatal("accepted a mismatched image from the server")
	}
	entries, err := os.ReadDir(filepath.Join(cache, otherBuildID))
	if err == nil && len(entries) > 0 {
		t.Errorf("mismatched download left %d file(s) in the cache", len(entries))
	}
}

// With several servers, the first that has the build-id answers and the rest
// are not queried.
func TestDebuginfodTriesServersInOrder(t *testing.T) {
	fixture := buildGoFixture(t, "-B 0x"+fixtureBuildID)
	empty, emptyHits := serveFixture(t, "nothing-here", "")
	full, fullHits := serveFixture(t, fixtureBuildID, fixture)

	d := NewDebuginfod(Options{URLs: []string{empty.URL, full.URL}, CacheDir: t.TempDir()})
	resolvesLeakyAlloc(t, d.Module(fixtureBuildID), fixture)
	if emptyHits.Load() != 1 || fullHits.Load() != 1 {
		t.Errorf("hits = %d,%d want 1,1", emptyHits.Load(), fullHits.Load())
	}
}

func TestValidateDebuginfodURL(t *testing.T) {
	if err := ValidateDebuginfodURL("https://debuginfod.example"); err != nil {
		t.Errorf("valid URL rejected: %v", err)
	}
	for _, bad := range []string{"", "debuginfod.example", "ftp://x.example", "https://"} {
		if err := ValidateDebuginfodURL(bad); err == nil {
			t.Errorf("ValidateDebuginfodURL(%q) = nil, want error", bad)
		}
	}
}

// The local answer wins every field it filled; the debug image only fills gaps,
// and never touches the identity fields.
func TestMergeSupplement(t *testing.T) {
	local := Frame{Module: "libfoo.so", Offset: 0x1500, BuildID: "abcd"}
	sup := Frame{Func: "do_work", File: "work.c", Line: 42, Module: "debuginfo", Offset: 0x99, BuildID: "abcd"}

	got := mergeSupplement(local, sup)
	want := Frame{Func: "do_work", File: "work.c", Line: 42, Module: "libfoo.so", Offset: 0x1500, BuildID: "abcd"}
	if got != want {
		t.Errorf("mergeSupplement = %+v, want %+v", got, want)
	}

	// A name found locally is not overwritten, and a local file:line is kept
	// whole — including its line, which must not be taken from the other frame.
	named := Frame{Func: "local_name", File: "local.c", Line: 7, Module: "libfoo.so", Offset: 0x1500}
	if got := mergeSupplement(named, sup); got != named {
		t.Errorf("mergeSupplement overwrote a local answer: %+v", got)
	}

	// Name locally, file:line only in DWARF that lives in the debug image.
	half := Frame{Func: "local_name", Module: "libfoo.so", Offset: 0x1500}
	got = mergeSupplement(half, sup)
	if got.Func != "local_name" || got.File != "work.c" || got.Line != 42 {
		t.Errorf("mergeSupplement half-filled = %+v", got)
	}
}

// stageFixture copies an ELF into the store's <build-id>/debuginfo layout.
func stageFixture(t *testing.T, cache, id, src string) {
	t.Helper()
	dir := filepath.Join(cache, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, debuginfoFile), b, 0o644); err != nil {
		t.Fatal(err)
	}
}
