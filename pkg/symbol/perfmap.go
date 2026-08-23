package symbol

import (
	"bufio"
	"io"
	"sort"
	"strconv"
	"strings"
)

// JIT frame resolution via the perf map file.
//
// A JIT'd frame has no ELF behind it. V8 and the JVM compile methods into
// anonymous executable memory at runtime, so /proc/<pid>/maps shows an
// unnamed region and every symbolization path in elf.go has nothing to read.
// Without this, a Node or JVM stack resolves to bare addresses — the runtimes
// where "which line allocated this" matters most are the ones that answer it
// least.
//
// The convention both ecosystems already implement is a plain text side file,
// /tmp/perf-<pid>.map, one line per compiled region:
//
//	<start-hex> <size-hex> <name>
//
// Node writes it under --perf-basic-prof; the JVM under perf-map-agent. It is
// the mechanism perf(1) itself uses, which is why it is worth supporting
// rather than inventing something.
//
// ─── The tier marker is the part that matters ───────────────────────────────
//
// V8 emits the SAME function repeatedly as it re-optimizes, distinguished only
// by a marker character:
//
//	JS:~hotSmall /app/server.js:2:18     interpreted
//	JS:+hotSmall /app/server.js:2:18     baseline
//	JS:^hotSmall /app/server.js:2:18     optimized
//
// Those are one function at three addresses, not three functions. A consumer
// diffing two deploys by call-site name would otherwise see functions appear
// and vanish purely because V8 decided to re-tier them under a slightly
// different load — noise indistinguishable from a real change, and produced by
// every warm-up. So the marker is stripped and the three normalize to one
// identity.

// perfSym is one compiled region from a perf map.
type perfSym struct {
	start, size uint64
	fn          string
	file        string
	line        int
}

// perfMap is a parsed perf map, sorted by start address for binary search.
type perfMap struct {
	syms []perfSym
	// size of the file when parsed; a JIT map only ever grows, so a change in
	// size is the cheap signal that there is more to read.
	size int64
}

// v8TierMarkers are the characters V8 puts before a function name to record
// which tier compiled it. See the header comment: they are re-tiering noise,
// not identity.
const v8TierMarkers = "~*+^-"

// parsePerfMap reads perf map lines from r.
//
// A malformed line is skipped rather than failing the parse: these files are
// written by a live process with no locking, so the last line can be torn
// mid-write, and losing one region is much better than losing the map.
func parsePerfMap(r io.Reader, size int64) *perfMap {
	pm := &perfMap{size: size}
	// Later entries supersede earlier ones at the same address: V8 reuses
	// regions after a deopt or a GC, and the newest line is the truth.
	byStart := make(map[uint64]perfSym, 512)

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20) // JIT names can be long
	for sc.Scan() {
		line := sc.Text()
		start, sz, name, ok := splitPerfMapLine(line)
		if !ok {
			continue
		}
		fn, file, ln := parsePerfMapName(name)
		byStart[start] = perfSym{start: start, size: sz, fn: fn, file: file, line: ln}
	}

	pm.syms = make([]perfSym, 0, len(byStart))
	for _, s := range byStart {
		pm.syms = append(pm.syms, s)
	}
	sort.Slice(pm.syms, func(i, j int) bool { return pm.syms[i].start < pm.syms[j].start })
	return pm
}

// splitPerfMapLine splits "<start-hex> <size-hex> <name>". The name is the
// remainder of the line and may contain spaces — it routinely does, since V8
// appends a source path.
func splitPerfMapLine(line string) (start, size uint64, name string, ok bool) {
	i := strings.IndexByte(line, ' ')
	if i <= 0 {
		return 0, 0, "", false
	}
	j := strings.IndexByte(line[i+1:], ' ')
	if j < 0 {
		return 0, 0, "", false
	}
	j += i + 1

	start, err := strconv.ParseUint(line[:i], 16, 64)
	if err != nil {
		return 0, 0, "", false
	}
	size, err = strconv.ParseUint(line[i+1:j], 16, 64)
	if err != nil {
		return 0, 0, "", false
	}
	name = strings.TrimSpace(line[j+1:])
	if name == "" {
		return 0, 0, "", false
	}
	return start, size, name, true
}

// parsePerfMapName splits a perf map symbol into a normalized function name
// and, where the runtime supplied one, a source location.
//
//	"JS:^hotSmall /app/server.js:2:18"  → "JS:hotSmall", "/app/server.js", 2
//	"JS:~ /app/server.js:6:23"          → "JS:<anonymous>", "/app/server.js", 6
//	"Builtin:RecordWriteSaveFP"         → "Builtin:RecordWriteSaveFP", "", 0
//	"Ljava/lang/String;::indexOf"       → "Ljava/lang/String;::indexOf", "", 0
func parsePerfMapName(name string) (fn, file string, line int) {
	fn = name

	if head, f, l, ok := splitTrailingLocation(fn); ok {
		fn, file, line = head, f, l
	}

	kind, rest, hasKind := splitJITKind(fn)
	if !hasKind {
		return fn, file, line
	}
	rest = strings.TrimLeft(rest, v8TierMarkers)
	if rest == "" {
		rest = "<anonymous>"
	}
	return kind + ":" + rest, file, line
}

// splitTrailingLocation separates a symbol's name from the source location V8
// appends to it.
//
// The obvious rule — split on the last space — breaks on a path containing a
// space ("JS:*h /app/my project/x.js:10:1" would keep "/app/my" as part of the
// name). The opposite rule, split on the first space, breaks on the names that
// legitimately contain one: V8 writes accessors as "get foo" and "set foo".
//
// So: prefer the LEFTMOST split whose remainder looks like a rooted path
// ("/…", "./…", or a scheme like "node:…"), which gets both of those right,
// and fall back to the rightmost parsable split for locations that are rooted
// in nothing — V8's "evalmachine.<anonymous>:1:1" and bare filenames.
func splitTrailingLocation(s string) (head, file string, line int, ok bool) {
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' {
			continue
		}
		rest := s[i+1:]
		if !looksRooted(rest) {
			continue
		}
		if f, l, good := splitFileLineCol(rest); good {
			return strings.TrimSpace(s[:i]), f, l, true
		}
	}
	if i := strings.LastIndexByte(s, ' '); i > 0 {
		if f, l, good := splitFileLineCol(s[i+1:]); good {
			return strings.TrimSpace(s[:i]), f, l, true
		}
	}
	return s, "", 0, false
}

// looksRooted reports whether a location candidate starts the way a path does:
// absolute, explicitly relative, or scheme-qualified (node:, file:, webpack:).
func looksRooted(s string) bool {
	switch {
	case strings.HasPrefix(s, "/"), strings.HasPrefix(s, "./"), strings.HasPrefix(s, "../"):
		return true
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ':' {
			return i > 0
		}
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return false
}

// splitJITKind separates a V8 kind prefix ("JS", "Builtin", "LazyCompile", …)
// from the rest of the symbol.
//
// The prefix is recognised structurally rather than from a fixed list, so a
// V8 version that adds a kind still parses: everything before the first colon
// must be plain letters, and the colon must not be doubled. That second
// condition is what keeps a JVM symbol like "Ljava/lang/String;::indexOf"
// intact — and so would a C++ "std::vector", were one ever to appear here.
func splitJITKind(s string) (kind, rest string, ok bool) {
	i := strings.IndexByte(s, ':')
	if i <= 0 || i+1 >= len(s) {
		return "", s, false
	}
	if s[i+1] == ':' {
		return "", s, false
	}
	for k := 0; k < i; k++ {
		if c := s[k]; c < 'A' || (c > 'Z' && c < 'a') || c > 'z' {
			return "", s, false
		}
	}
	return s[:i], s[i+1:], true
}

// splitFileLineCol parses "<path>:<line>" or "<path>:<line>:<col>". The path
// must be non-empty and the numeric parts must really be numeric, so an
// ordinary symbol containing a colon is not mistaken for a location.
func splitFileLineCol(s string) (file string, line int, ok bool) {
	i := strings.LastIndexByte(s, ':')
	if i <= 0 {
		return "", 0, false
	}
	n, err := strconv.Atoi(s[i+1:])
	if err != nil || n < 0 {
		return "", 0, false
	}
	head := s[:i]

	// "path:line:col" — the number just parsed was the column; take the line
	// from the next field left.
	if j := strings.LastIndexByte(head, ':'); j > 0 {
		if l, err := strconv.Atoi(head[j+1:]); err == nil && l > 0 {
			return head[:j], l, true
		}
	}
	if n <= 0 || head == "" {
		return "", 0, false
	}
	return head, n, true
}

// lookup resolves an address to its compiled region.
func (p *perfMap) lookup(addr uint64) (perfSym, bool) {
	if p == nil || len(p.syms) == 0 {
		return perfSym{}, false
	}
	i := sort.Search(len(p.syms), func(i int) bool { return p.syms[i].start > addr })
	if i == 0 {
		return perfSym{}, false
	}
	s := p.syms[i-1]
	if addr >= s.start+s.size {
		return perfSym{}, false // in the gap after a region, not in it
	}
	return s, true
}

// frame renders a resolved JIT symbol.
//
// Module is the literal "[jit]" rather than a filename because there is no
// file: the code was generated into anonymous memory and exists nowhere on
// disk. Saying so is more useful than leaving it blank, which would read as
// "we failed to identify the module".
func (s perfSym) frame(addr uint64) Frame {
	return Frame{
		Func:   s.fn,
		File:   s.file,
		Line:   s.line,
		Module: jitModuleName,
		Offset: addr - s.start,
	}
}

// jitModuleName marks a frame as runtime-generated code with no backing file.
const jitModuleName = "[jit]"
