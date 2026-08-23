//go:build linux

package symbol

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A live Node process, end to end: start it with --perf-basic-prof, find the
// map the way the Symbolizer does, and resolve a JIT address through the
// public API. This is the part unit tests over a fixture cannot cover — that
// the file is located at all for a running process.
func TestSymbolizeResolvesLiveNodeJITFrame(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not on PATH")
	}

	dir := t.TempDir()
	script := filepath.Join(dir, "hot.js")
	src := "function hotLoop(n){let s=0;for(let i=0;i<n;i++)s+=i*7;return s}\n" +
		"let a=0;const t=setInterval(()=>{a+=hotLoop(300000)},2);\n" +
		"setTimeout(()=>{clearInterval(t);console.error(a)},60000);\n"
	if err := os.WriteFile(script, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(node, "--perf-basic-prof", script)
	cmd.Dir = dir
	if err := cmd.Start(); err != nil {
		t.Skipf("start node: %v", err)
	}
	pid := cmd.Process.Pid
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		_ = os.Remove(fmt.Sprintf("/tmp/perf-%d.map", pid))
	})

	// Wait for V8 to compile hotLoop and flush it to the map. The tier does
	// not matter — any entry naming the function proves the plumbing.
	var entry string
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) && entry == "" {
		entry = findMapEntry(fmt.Sprintf("/tmp/perf-%d.map", pid), "hotLoop")
		if entry == "" {
			time.Sleep(200 * time.Millisecond)
		}
	}
	if entry == "" {
		t.Skip("node did not emit a hotLoop entry; --perf-basic-prof may be unsupported in this build")
	}

	start, _, _, ok := splitPerfMapLine(entry)
	if !ok {
		t.Fatalf("unparsable map line from a real node: %q", entry)
	}

	s, err := NewSymbolizer(pid)
	if err != nil {
		t.Fatalf("NewSymbolizer: %v", err)
	}
	defer s.Close()

	fr := s.Symbolize(start + 1)
	if fr.Func != "JS:hotLoop" {
		t.Errorf("Func = %q, want JS:hotLoop (line was %q)", fr.Func, entry)
	}
	if !strings.HasSuffix(fr.File, "hot.js") {
		t.Errorf("File = %q, want …/hot.js", fr.File)
	}
	if fr.Line != 1 {
		t.Errorf("Line = %d, want 1", fr.Line)
	}
	if fr.Module != jitModuleName {
		t.Errorf("Module = %q, want %q", fr.Module, jitModuleName)
	}

	// An address in no JIT region and no mapped module must still degrade
	// rather than borrow a neighbouring symbol.
	if bad := s.Symbolize(0x10); bad.Func != "" {
		t.Errorf("bogus address resolved to %q", bad.Func)
	}
}

func findMapEntry(path, needle string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if strings.Contains(sc.Text(), needle) {
			return sc.Text()
		}
	}
	return ""
}

func TestNSPIDsReadsOwnStatus(t *testing.T) {
	pids := nsPIDs(os.Getpid())
	if len(pids) == 0 {
		t.Skip("kernel does not report NSpid")
	}
	if pids[0] != os.Getpid() {
		t.Errorf("NSpid[0] = %d, want our own pid %d", pids[0], os.Getpid())
	}
}

func TestNSPIDsMissingProcess(t *testing.T) {
	if got := nsPIDs(-1); got != nil {
		t.Errorf("nsPIDs(-1) = %v, want nil", got)
	}
}

// The innermost namespace pid is what a containerized runtime names its file
// with, so it must be tried first.
func TestPerfMapPIDsPrefersInnermostNamespace(t *testing.T) {
	s := &Symbolizer{pid: os.Getpid()}
	pids := s.perfMapPIDs()
	if len(pids) == 0 {
		t.Fatal("perfMapPIDs returned nothing")
	}
	if pids[len(pids)-1] != os.Getpid() {
		t.Errorf("outermost pid = %d, want %d last", pids[len(pids)-1], os.Getpid())
	}
}
