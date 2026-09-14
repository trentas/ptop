package symbol

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Off-ELF symbol sources (#119).
//
// The local cascade — .gopclntab → .symtab/.dynsym → DWARF → perf map →
// module+0xoffset — resolves everything whose symbols travel INSIDE the mapped
// image: Go even stripped, C/C++ built with -g, Node and JVM JIT. What it
// cannot name is a third-party binary shipped stripped (-s, no DWARF, no perf
// map). The heap axis, the only one carrying func and file:line, then produces
// addresses and nothing else.
//
// What is missing there is a symbol SOURCE, not an identity: every Frame
// already carries the module's GNU build-id, which is exactly the key the
// ecosystem uses to match a binary with symbols stored outside it. So this file
// adds the lookup — a local symbol store (a vendor bundle unpacked on disk),
// and debuginfod over HTTP when the operator asks for it.
//
// Four properties are load-bearing, in roughly this order:
//
//   - A build-id that does not match is ABSENCE, not a best guess. A file is
//     parsed and its own build-id compared to the one asked for before a single
//     symbol is taken from it; anything else is discarded and the frame stays
//     module+0xoffset. A wrong symbol is worse than no symbol — it points a
//     reader at a line of source that has nothing to do with what ran, and
//     unlike a bare address it does not look like a gap.
//   - The network is OFF unless someone asked. A profiler that reaches out to
//     the internet because a binary happened to be stripped is a posture
//     decision, not a convenience. The zero Options resolves nothing at all,
//     not even from disk.
//   - Local resolution stays local. This source is consulted only for what the
//     mapped ELF could not answer, so an image carrying its own symbols never
//     pays a disk or network lookup.
//   - A build-id is looked up exactly once per process. Both the hit and the
//     miss are remembered, so a stripped module costs one lookup rather than
//     one per frame, and a primed cache costs no network at all.

// DefaultDebuginfodTimeout bounds one fetch end to end (connect, headers and
// body). Generous because a debuginfo file for a large C++ image is tens to
// hundreds of megabytes, and finite because the caller is a collector's publish
// loop — see Debuginfod.Module.
const DefaultDebuginfodTimeout = 30 * time.Second

// maxDebuginfoBytes caps one downloaded file. A debuginfod server is named by
// the operator and is normally trusted, but "normally" is not a disk budget:
// the download goes to the cache directory, and an unbounded write there fills
// whatever filesystem it lives on.
const maxDebuginfoBytes int64 = 2 << 30

// debuginfoFile is the file name inside a build-id directory. It matches the
// layout elfutils' debuginfod client uses, which is what makes an already
// populated client cache usable as-is.
const debuginfoFile = "debuginfo"

const debuginfodUserAgent = "ptop/debuginfod"

// Options names the optional symbol sources consulted AFTER the local ELF
// cascade. The zero value is "local ELF only", which is the default everywhere
// — see the network note above.
type Options struct {
	// URLs are debuginfod base URLs, tried in order until one has the build-id.
	// Empty means no network: CacheDir, if set, is then the only source.
	URLs []string

	// CacheDir is a local symbol store laid out as <dir>/<build-id>/debuginfo.
	// It is read before the network and written after a successful fetch, so a
	// module is downloaded once per host rather than once per capture — and a
	// vendor symbol bundle unpacked into that layout resolves with no network
	// configured at all. Empty disables both the read and the write.
	CacheDir string

	// Timeout bounds one fetch. 0 takes DefaultDebuginfodTimeout.
	Timeout time.Duration
}

// Enabled reports whether any off-ELF source is configured. The zero Options is
// not enabled, which is what makes "off by default" the default rather than a
// flag someone has to remember to pass.
func (o Options) Enabled() bool { return len(o.URLs) > 0 || o.CacheDir != "" }

// Debuginfod resolves a build-id to the separate debug image carrying that
// module's symbols. Safe for concurrent use and shared across collectors: the
// heap, futex and security symbolizers of one target hold the same instance, so
// a module is fetched once for all three.
type Debuginfod struct {
	opts   Options
	client *http.Client

	mu      sync.Mutex
	entries map[string]*debugEntry
}

// debugEntry is one build-id's resolution, done exactly once. A nil mod after
// once fires is a remembered miss, not "not tried yet".
type debugEntry struct {
	once sync.Once
	mod  *Module
}

// NewDebuginfod builds the source described by o, or returns nil when o
// configures nothing. A nil *Debuginfod is usable — every method tolerates it —
// so callers can pass the result straight through without a branch.
func NewDebuginfod(o Options) *Debuginfod {
	if !o.Enabled() {
		return nil
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultDebuginfodTimeout
	}
	return &Debuginfod{
		opts:    o,
		client:  &http.Client{Timeout: o.Timeout},
		entries: make(map[string]*debugEntry),
	}
}

// Module returns the separate debug image for buildID, or nil when no
// configured source has it (which is the ordinary outcome, and degrades to
// module+0xoffset upstream).
//
// It blocks on I/O — including the network, when URLs are configured. A caller
// on a collector's publish path therefore stalls once per stripped module,
// bounded by Options.Timeout. That is deliberate: the callers cache what they
// get, permanently, so returning "not yet" would cache an unresolved frame for
// the life of the process and the symbols would never appear.
func (d *Debuginfod) Module(buildID string) *Module {
	if d == nil {
		return nil
	}
	id, ok := normalizeBuildID(buildID)
	if !ok {
		return nil
	}

	d.mu.Lock()
	e := d.entries[id]
	if e == nil {
		e = &debugEntry{}
		d.entries[id] = e
	}
	d.mu.Unlock()

	// Concurrent callers for the same id block here on the first one rather
	// than each starting their own download.
	e.once.Do(func() { e.mod = d.resolve(id) })
	return e.mod
}

// resolve runs the sources in order: the local store first, so a primed cache
// or an unpacked vendor bundle never touches the network, then each server.
func (d *Debuginfod) resolve(id string) *Module {
	if p := d.cachedPath(id); p != "" {
		m, err := loadVerified(p, id)
		switch {
		case err == nil:
			return m
		case !errors.Is(err, fs.ErrNotExist):
			// A file IS there and cannot be used. Say so — silence here reads
			// as "no symbols published" when it is really "the wrong ones are".
			fmt.Fprintf(os.Stderr, "[ptop] symbols: %s: %v\n", p, err)
		}
	}

	for _, base := range d.opts.URLs {
		m, err := d.fetch(base, id)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ptop] debuginfod: %s %s: %v\n", base, shortID(id), err)
			continue
		}
		if m != nil {
			fmt.Fprintf(os.Stderr, "[ptop] debuginfod: symbols for build-id %s from %s\n", shortID(id), base)
			return m
		}
	}
	return nil
}

// fetch downloads one build-id from one server. A 404 is (nil, nil): that
// server simply does not publish this module, which is not an error worth
// printing for every server in the list.
func (d *Debuginfod) fetch(base, id string) (*Module, error) {
	u, err := debuginfoURL(base, id)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), d.opts.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", debuginfodUserAgent)

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, nil
	default:
		return nil, errors.New(resp.Status)
	}

	// Always land in a temp file first and verify there. Promoting into the
	// cache before the build-id is checked would persist a mismatched file and
	// make one bad server poison every later run on this host.
	tmp, err := d.download(id, resp.Body)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp)

	m, err := loadVerified(tmp, id)
	if err != nil {
		return nil, err
	}
	d.promote(tmp, id)
	return m, nil
}

// download streams body to a temp file next to its eventual cache location
// (same filesystem, so promote is a rename) and returns the path.
func (d *Debuginfod) download(id string, body io.Reader) (string, error) {
	dir := os.TempDir()
	if cd := d.cacheDirFor(id); cd != "" {
		if err := os.MkdirAll(cd, 0o755); err == nil {
			dir = cd
		}
	}
	f, err := os.CreateTemp(dir, debuginfoFile+"-*.part")
	if err != nil {
		return "", err
	}
	tmp := f.Name()

	n, err := io.Copy(f, io.LimitReader(body, maxDebuginfoBytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > maxDebuginfoBytes {
		err = fmt.Errorf("debuginfo larger than %d bytes", maxDebuginfoBytes)
	}
	if err != nil {
		os.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

// promote moves a verified file into the cache. Failure is not an error the
// caller cares about: the symbols are already parsed and usable for this run,
// and the only cost is fetching again next time.
func (d *Debuginfod) promote(tmp, id string) {
	dir := d.cacheDirFor(id)
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	_ = os.Rename(tmp, filepath.Join(dir, debuginfoFile))
}

// cacheDirFor is the build-id's directory in the local store, or "" when no
// store is configured.
func (d *Debuginfod) cacheDirFor(id string) string {
	if d.opts.CacheDir == "" {
		return ""
	}
	return filepath.Join(d.opts.CacheDir, id)
}

// cachedPath is where this build-id's debug image would be on disk, or "".
func (d *Debuginfod) cachedPath(id string) string {
	dir := d.cacheDirFor(id)
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, debuginfoFile)
}

// loadVerified parses path as ELF and returns it ONLY if the image's own
// build-id is the one asked for.
//
// This is the check the whole feature rests on. A separate debug file keeps its
// ELF note sections verbatim (objcopy --only-keep-debug preserves SHT_NOTE
// contents while blanking the rest), so the id is there to be compared — and an
// image that does not carry it cannot be tied to the target at all, which is a
// refusal rather than a reason to trust the filename.
func loadVerified(path, id string) (*Module, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	m, err := OpenModule(f, path)
	if err != nil {
		return nil, err
	}
	switch got := m.BuildID(); {
	case got == "":
		return nil, errors.New("no build-id note: cannot be matched to the target")
	case !strings.EqualFold(got, id):
		return nil, fmt.Errorf("build-id is %s, wanted %s", shortID(got), shortID(id))
	}
	return m, nil
}

// normalizeBuildID lowercases and validates a build-id. The value comes out of
// the target's own ELF and is about to become a path segment and a URL segment,
// so anything that is not plain hex is rejected outright rather than escaped.
func normalizeBuildID(id string) (string, bool) {
	if len(id) < 8 || len(id) > 128 || len(id)%2 != 0 {
		return "", false
	}
	out := []byte(strings.ToLower(id))
	for _, c := range out {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", false
		}
	}
	return string(out), true
}

// debuginfoURL builds the debuginfod query for a build-id. The protocol is
// <base>/buildid/<hex>/debuginfo.
func debuginfoURL(base, id string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil {
		return "", fmt.Errorf("bad server URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme %q (want http or https)", u.Scheme)
	}
	if u.Host == "" {
		return "", errors.New("server URL has no host")
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/buildid/" + id + "/" + debuginfoFile
	u.RawQuery, u.Fragment = "", ""
	return u.String(), nil
}

// ValidateDebuginfodURL reports whether base can be turned into a debuginfod
// request. Callers use it at startup: a typo that only surfaces as a per-module
// warning mid-capture is a typo nobody sees in time.
func ValidateDebuginfodURL(base string) error {
	_, err := debuginfoURL(base, strings.Repeat("0", 40))
	return err
}

// ParseDebuginfodURLs splits a server list. DEBUGINFOD_URLS is space-separated
// by convention; commas are accepted too because a command-line flag invites
// them. Empty entries are dropped.
func ParseDebuginfodURLs(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f != "" {
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// DebuginfodURLsFromEnv returns the servers named by DEBUGINFOD_URLS, the
// variable the rest of the ecosystem reads. Note that reading it is not the
// same as using it: ptop consults this only once the operator has opted into
// network lookup, so an environment that happens to carry the variable does not
// by itself send a profiler to the internet.
func DebuginfodURLsFromEnv() []string { return ParseDebuginfodURLs(os.Getenv("DEBUGINFOD_URLS")) }

// DefaultCacheDir is where elfutils' debuginfod client keeps its cache, which
// is deliberately the same place ptop uses: a host that already primed it
// resolves offline, and what ptop fetches is there for the next tool.
//
// Returns "" when no home directory can be determined, which callers read as
// "no store" rather than falling back to somewhere surprising.
func DefaultCacheDir() string {
	if p := os.Getenv("DEBUGINFOD_CACHE_PATH"); p != "" {
		return p
	}
	if p := os.Getenv("XDG_CACHE_HOME"); p != "" {
		return filepath.Join(p, "debuginfod_client")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".cache", "debuginfod_client")
}

// DebuginfodTimeoutFromEnv reads DEBUGINFOD_TIMEOUT (whole seconds), or 0 when
// it is unset or unusable.
func DebuginfodTimeoutFromEnv() time.Duration {
	v := strings.TrimSpace(os.Getenv("DEBUGINFOD_TIMEOUT"))
	if v == "" {
		return 0
	}
	secs, err := time.ParseDuration(v + "s")
	if err != nil || secs <= 0 {
		return 0
	}
	return secs
}

// shortID abbreviates a build-id for messages. The full 40 hex digits carry no
// information a reader uses when scanning stderr.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// mergeSupplement folds a separate debug image's answer into the one the mapped
// image gave. The local frame wins every field it filled: the debug image is a
// second opinion about NAMES, never about identity — Module, Offset and BuildID
// stay as the mapping reported them, since the debug file is itself called
// "debuginfo" and its load base need not match the image's.
func mergeSupplement(local, sup Frame) Frame {
	if local.Func == "" {
		local.Func = sup.Func
	}
	if local.File == "" && sup.File != "" {
		local.File, local.Line = sup.File, sup.Line
	}
	return local
}

// Option configures a Symbolizer.
type Option func(*Symbolizer)

// WithDebuginfod attaches an off-ELF symbol source, consulted only for what the
// mapped image could not answer. A nil source is a no-op, so the caller does
// not branch on whether the operator configured one.
func WithDebuginfod(d *Debuginfod) Option {
	return func(s *Symbolizer) { s.debuginfod = d }
}
