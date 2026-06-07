//go:build linux

package symbol

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// segment is one executable, file-backed mapping from /proc/<pid>/maps.
type segment struct {
	start, end uint64
	fileOff    uint64
	path       string
}

// Symbolizer resolves runtime addresses of a live process to Frames. It parses
// the process's executable mappings once at construction and lazily opens +
// caches each backing ELF module on first use.
type Symbolizer struct {
	pid  int
	segs []segment

	mu   sync.Mutex
	mods map[string]*Module // by resolved path; nil value = open failed

	buildOnce   sync.Once
	execBuildID string
}

// NewSymbolizer snapshots pid's executable mappings. The set of mapped modules
// is assumed stable for the lifetime of the symbolizer (true for the steady
// state ptop observes); dlopen after construction won't be picked up.
func NewSymbolizer(pid int) (*Symbolizer, error) {
	segs, err := parseMaps(pid)
	if err != nil {
		return nil, err
	}
	return &Symbolizer{pid: pid, segs: segs, mods: make(map[string]*Module)}, nil
}

// Symbolize resolves a runtime address. It never errors: an address in an
// unmapped / anonymous / unreadable region degrades to a bare Frame{Offset}.
func (s *Symbolizer) Symbolize(addr uint64) Frame {
	seg, ok := s.segFor(addr)
	if !ok {
		return Frame{Offset: addr}
	}
	m := s.module(seg.path)
	if m == nil {
		return Frame{Module: filepath.Base(seg.path), Offset: addr - seg.start}
	}
	v, ok := fileVaddr(addr, seg.start, seg.fileOff, m.loads)
	if !ok {
		return Frame{Module: m.name, Offset: addr - seg.start, BuildID: m.buildID}
	}
	return m.Resolve(v)
}

func (s *Symbolizer) Close() error { return nil }

// ProcessBuildID returns the GNU build-id (hex) of the target's main
// executable, or "" if it has none / can't be read. It is a stable per-process
// key for the stack ids this symbolizer's process hands out: the same stack id
// denotes a different stack once the binary changes. Computed once, lazily.
func (s *Symbolizer) ProcessBuildID() string {
	s.buildOnce.Do(func() {
		// /proc/<pid>/exe is a magic symlink the kernel resolves to the running
		// image — readable even when the on-disk path is gone (deleted/overlay).
		f, err := os.Open(fmt.Sprintf("/proc/%d/exe", s.pid))
		if err != nil {
			return
		}
		defer f.Close()
		if m, err := OpenModule(f, "exe"); err == nil {
			s.execBuildID = m.buildID
		}
	})
	return s.execBuildID
}

func (s *Symbolizer) segFor(addr uint64) (segment, bool) {
	for _, sg := range s.segs {
		if addr >= sg.start && addr < sg.end {
			return sg, true
		}
	}
	return segment{}, false
}

// module opens and caches the ELF backing path. A cached nil means a prior open
// failed (negative cache) so we don't retry a bad path every frame.
func (s *Symbolizer) module(path string) *Module {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m, ok := s.mods[path]; ok {
		return m
	}
	m := s.openModule(path)
	s.mods[path] = m
	return m
}

func (s *Symbolizer) openModule(path string) *Module {
	f, err := s.openModuleFile(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	m, err := OpenModule(f, path)
	if err != nil {
		return nil
	}
	return m
}

// openModuleFile opens the file backing a mapping. It prefers the path as seen
// from the target's mount namespace (/proc/<pid>/root<path>) so the on-disk
// bytes match the running image inside containers; falls back to the bare path,
// then to /proc/<pid>/map_files (which resolves even deleted/overlay inodes).
func (s *Symbolizer) openModuleFile(path string) (*os.File, error) {
	path = strings.TrimSuffix(path, " (deleted)")
	candidates := []string{
		fmt.Sprintf("/proc/%d/root%s", s.pid, path),
		path,
	}
	for _, c := range candidates {
		if f, err := os.Open(c); err == nil {
			return f, nil
		}
	}
	// Last resort: the map_files symlink keyed by the segment's address range.
	if sg, ok := s.segByPath(path); ok {
		mf := fmt.Sprintf("/proc/%d/map_files/%x-%x", s.pid, sg.start, sg.end)
		if f, err := os.Open(mf); err == nil {
			return f, nil
		}
	}
	return nil, os.ErrNotExist
}

func (s *Symbolizer) segByPath(path string) (segment, bool) {
	for _, sg := range s.segs {
		if strings.TrimSuffix(sg.path, " (deleted)") == path {
			return sg, true
		}
	}
	return segment{}, false
}

// parseMaps returns the executable, file-backed segments of pid. Anonymous,
// non-executable, and pseudo ([vdso], [stack], …) mappings are skipped.
func parseMaps(pid int) ([]segment, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, fmt.Errorf("open maps of %d: %w", pid, err)
	}
	defer f.Close()

	var segs []segment
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		if !strings.Contains(fields[1], "x") {
			continue // executable segments only
		}
		path := strings.Join(fields[5:], " ")
		if !strings.HasPrefix(path, "/") {
			continue // skip [vdso]/[stack]/anon
		}
		dash := strings.IndexByte(fields[0], '-')
		if dash < 0 {
			continue
		}
		start, e1 := strconv.ParseUint(fields[0][:dash], 16, 64)
		end, e2 := strconv.ParseUint(fields[0][dash+1:], 16, 64)
		fileOff, e3 := strconv.ParseUint(fields[2], 16, 64)
		if e1 != nil || e2 != nil || e3 != nil {
			continue
		}
		segs = append(segs, segment{start: start, end: end, fileOff: fileOff, path: path})
	}
	return segs, sc.Err()
}
