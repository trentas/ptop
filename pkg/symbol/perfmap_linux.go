//go:build linux

package symbol

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Locating a live process's perf map.
//
// Two things make the path less obvious than /tmp/perf-<pid>.map:
//
//  1. The runtime names the file with the pid it can see, which inside a
//     container is its pid in its OWN namespace, not the one ptop observes it
//     by. /proc/<pid>/status carries the whole chain in NSpid.
//  2. The file is in the target's /tmp, which in a container is not ours.
//     /proc/<pid>/root crosses into its mount namespace.
//
// Getting either wrong does not fail loudly — it silently finds no map and
// every JIT frame stays a bare address, which is exactly the state this is
// meant to fix. So both are resolved explicitly, and the host path is tried
// too for the ordinary uncontainerized case.

// perfMapReloadInterval bounds how often a miss re-reads the file. A JIT map
// grows for the life of the process, so a miss can always mean "compiled since
// we last read" — without a bound, a stream of genuinely unresolvable
// addresses would re-read the file on every single frame.
const perfMapReloadInterval = 2 * time.Second

// perfMapFor returns the parsed perf map for the target, reloading it when the
// file has grown since the last read. nil when the process has none, which is
// the normal case for anything that is not a JIT runtime.
func (s *Symbolizer) perfMapFor() *perfMap {
	s.jitMu.Lock()
	defer s.jitMu.Unlock()

	now := time.Now()
	if s.jitMap != nil && now.Sub(s.jitCheckedAt) < perfMapReloadInterval {
		return s.jitMap
	}
	// A process with no map is the common case; do not stat it on every frame.
	if s.jitMap == nil && !s.jitCheckedAt.IsZero() && now.Sub(s.jitCheckedAt) < perfMapReloadInterval {
		return nil
	}
	s.jitCheckedAt = now

	path, fi := s.findPerfMap()
	if path == "" {
		return s.jitMap
	}
	if s.jitMap != nil && fi.Size() == s.jitMap.size {
		return s.jitMap // unchanged since the last read
	}
	f, err := os.Open(path)
	if err != nil {
		return s.jitMap
	}
	defer f.Close()
	s.jitMap = parsePerfMap(bufio.NewReader(f), fi.Size())
	return s.jitMap
}

// findPerfMap locates the map file, preferring the target's own mount
// namespace so a containerized runtime is found at all.
func (s *Symbolizer) findPerfMap() (string, os.FileInfo) {
	for _, pid := range s.perfMapPIDs() {
		for _, cand := range []string{
			fmt.Sprintf("/proc/%d/root/tmp/perf-%d.map", s.pid, pid),
			fmt.Sprintf("/tmp/perf-%d.map", pid),
		} {
			if fi, err := os.Stat(cand); err == nil && fi.Mode().IsRegular() {
				return cand, fi
			}
		}
	}
	return "", nil
}

// perfMapPIDs returns the pids the target may have named its map file with:
// the innermost namespace pid first (what a containerized runtime writes),
// then the pid we observe it by.
func (s *Symbolizer) perfMapPIDs() []int {
	pids := nsPIDs(s.pid)
	// Innermost namespace last in NSpid; that is the one the process sees as
	// its own getpid(), so try it first.
	for i, j := 0, len(pids)-1; i < j; i, j = i+1, j-1 {
		pids[i], pids[j] = pids[j], pids[i]
	}
	for _, p := range pids {
		if p == s.pid {
			return pids
		}
	}
	return append(pids, s.pid)
}

// nsPIDs reads the NSpid line of /proc/<pid>/status: the process's pid in each
// nested pid namespace, outermost first. Returns nil when the kernel does not
// report it (pre-4.1) or the file is unreadable.
func nsPIDs(pid int) []int {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "NSpid:") {
			continue
		}
		var out []int
		for _, fld := range strings.Fields(line[len("NSpid:"):]) {
			if n, err := strconv.Atoi(fld); err == nil {
				out = append(out, n)
			}
		}
		return out
	}
	return nil
}
