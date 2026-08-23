package symbol

import (
	"os"
	"strings"
	"testing"
)

func loadFixtureMap(t *testing.T) *perfMap {
	t.Helper()
	f, err := os.Open("testdata/perfmap/node22.map")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return parsePerfMap(f, fi.Size())
}

// The single most important property. V8 emits one function once per
// optimization tier, marked ~ + ^ *. Left alone, a deploy diff keyed on
// function name would show functions appearing and disappearing every time V8
// re-tiered them under a slightly different load — churn produced by warm-up,
// indistinguishable from a real change. The fixture is a real Node 22 map and
// contains all four tiers of the same function.
func TestPerfMapNormalizesV8Tiers(t *testing.T) {
	pm := loadFixtureMap(t)

	var tiers []perfSym
	for _, s := range pm.syms {
		if strings.HasSuffix(s.fn, "hotSmall") {
			tiers = append(tiers, s)
		}
	}
	if len(tiers) < 3 {
		t.Fatalf("fixture should carry several tiers of hotSmall, got %d", len(tiers))
	}
	for _, s := range tiers {
		if s.fn != "JS:hotSmall" {
			t.Errorf("Func = %q, want JS:hotSmall (tier marker not stripped)", s.fn)
		}
		if s.file != "/app/jittarget.js" || s.line != 2 {
			t.Errorf("location = %s:%d, want /app/jittarget.js:2", s.file, s.line)
		}
	}
	// They are distinct compiled regions, so they must remain distinct
	// entries — normalizing the NAME must not collapse the address ranges.
	seen := map[uint64]bool{}
	for _, s := range tiers {
		if seen[s.start] {
			t.Errorf("duplicate start %#x: distinct tiers were merged", s.start)
		}
		seen[s.start] = true
	}
}

func TestParsePerfMapName(t *testing.T) {
	cases := []struct {
		in       string
		fn, file string
		line     int
	}{
		{"JS:^hotSmall /app/server.js:2:18", "JS:hotSmall", "/app/server.js", 2},
		{"JS:~hotSmall /app/server.js:2:18", "JS:hotSmall", "/app/server.js", 2},
		{"JS:*handler /app/a b/x.js:10:1", "JS:handler", "/app/a b/x.js", 10},
		// V8 spells accessors with a space in the NAME, so the location
		// cannot simply be "everything after the first space".
		{"JS:^get length /app/x.js:5:1", "JS:get length", "/app/x.js", 5},
		{"JS:^set value ./lib/y.js:9:3", "JS:set value", "./lib/y.js", 9},
		// Node's builtins are scheme-qualified, not absolute paths.
		{"JS:^requireBuiltin node:internal/bootstrap/realm:420:24",
			"JS:requireBuiltin", "node:internal/bootstrap/realm", 420},
		{"JS:^normalizeString node:path:92:25", "JS:normalizeString", "node:path", 92},
		// Rooted in nothing: the rightmost-parsable fallback.
		{"Eval:~ evalmachine.<anonymous>:1:1", "Eval:<anonymous>", "evalmachine.<anonymous>", 1},
		// Anonymous function: V8 emits the marker with no name at all.
		{"JS:~ /app/server.js:6:23", "JS:<anonymous>", "/app/server.js", 6},
		{"Eval:~ /app/server.js:1:1", "Eval:<anonymous>", "/app/server.js", 1},
		// No location at all.
		{"Builtin:RecordWriteSaveFP", "Builtin:RecordWriteSaveFP", "", 0},
		{"Stub:CEntryStub", "Stub:CEntryStub", "", 0},
		// Older V8 spelling.
		{"LazyCompile:*parse /app/p.js:44:9", "LazyCompile:parse", "/app/p.js", 44},
		// line only, no column.
		{"JS:^f /app/s.js:7", "JS:f", "/app/s.js", 7},
		// A JVM symbol: no kind prefix to strip, and the doubled colon must
		// survive intact.
		{"Ljava/lang/String;::indexOf", "Ljava/lang/String;::indexOf", "", 0},
		{"Lcom/acme/Svc;::handle", "Lcom/acme/Svc;::handle", "", 0},
		// A bare name with no colon at all.
		{"my_native_thunk", "my_native_thunk", "", 0},
		// A colon that is not a kind prefix (digits before it).
		{"0x42:thing", "0x42:thing", "", 0},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			fn, file, line := parsePerfMapName(c.in)
			if fn != c.fn || file != c.file || line != c.line {
				t.Errorf("= %q, %q, %d; want %q, %q, %d", fn, file, line, c.fn, c.file, c.line)
			}
		})
	}
}

func TestSplitPerfMapLine(t *testing.T) {
	start, size, name, ok := splitPerfMapLine("edfc50005260 488 JS:+hotSmall /app/x.js:2:18")
	if !ok || start != 0xedfc50005260 || size != 0x488 || name != "JS:+hotSmall /app/x.js:2:18" {
		t.Errorf("= %#x, %#x, %q, %v", start, size, name, ok)
	}

	// A perf map is written by a live process with no locking, so the tail can
	// be torn mid-write. A bad line must be skipped, never fail the parse.
	for _, bad := range []string{"", "onlyonefield", "notahex 10 name", "1000 nothex name", "1000 20", "1000 20   "} {
		if _, _, _, ok := splitPerfMapLine(bad); ok {
			t.Errorf("accepted malformed line %q", bad)
		}
	}
}

func TestPerfMapTornTailStillParses(t *testing.T) {
	in := "1000 100 JS:^a /x.js:1:1\n2000 200 JS:^b /x.js:2:1\n3000 10"
	pm := parsePerfMap(strings.NewReader(in), int64(len(in)))
	if len(pm.syms) != 2 {
		t.Fatalf("len = %d, want 2 (the torn last line dropped, the rest kept)", len(pm.syms))
	}
	if _, ok := pm.lookup(0x2050); !ok {
		t.Error("the complete entries before the torn line were lost")
	}
}

func TestPerfMapLookup(t *testing.T) {
	in := "1000 100 JS:^a /x.js:1:1\n3000 100 JS:^b /x.js:9:1\n"
	pm := parsePerfMap(strings.NewReader(in), int64(len(in)))

	cases := []struct {
		addr uint64
		want string
	}{
		{0x0fff, ""},     // before the first region
		{0x1000, "JS:a"}, // first byte
		{0x10ff, "JS:a"}, // last byte
		{0x1100, ""},     // one past the end — the gap, not the region
		{0x2000, ""},     // between regions
		{0x3050, "JS:b"},
		{0x3100, ""}, // past the last region
	}
	for _, c := range cases {
		sym, ok := pm.lookup(c.addr)
		if c.want == "" {
			if ok {
				t.Errorf("lookup(%#x) resolved to %q, want a miss", c.addr, sym.fn)
			}
			continue
		}
		if !ok || sym.fn != c.want {
			t.Errorf("lookup(%#x) = %q,%v want %q", c.addr, sym.fn, ok, c.want)
		}
	}

	if _, ok := (*perfMap)(nil).lookup(0x1000); ok {
		t.Error("nil perfMap resolved an address")
	}
}

// V8 reuses an address after a deopt, writing a new line for the same start.
// The later line is the truth.
func TestPerfMapLastEntryWinsAtSameAddress(t *testing.T) {
	in := "1000 100 JS:~old /x.js:1:1\n1000 100 JS:^new /x.js:1:1\n"
	pm := parsePerfMap(strings.NewReader(in), int64(len(in)))
	sym, ok := pm.lookup(0x1050)
	if !ok || sym.fn != "JS:new" {
		t.Errorf("lookup = %q,%v want JS:new (the later line)", sym.fn, ok)
	}
}

// A JIT frame has no file behind it, and the frame must say that rather than
// leave the module blank, which reads as a failure to identify it.
func TestPerfSymFrame(t *testing.T) {
	s := perfSym{start: 0x1000, size: 0x100, fn: "JS:hotSmall", file: "/app/x.js", line: 2}
	fr := s.frame(0x1040)
	if fr.Func != "JS:hotSmall" || fr.File != "/app/x.js" || fr.Line != 2 {
		t.Errorf("frame = %+v", fr)
	}
	if fr.Module != "[jit]" {
		t.Errorf("Module = %q, want [jit]", fr.Module)
	}
	if fr.Offset != 0x40 {
		t.Errorf("Offset = %#x, want 0x40", fr.Offset)
	}
}
