package bpf

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// fullyPrivileged is the capability set the README now teaches, as measured on
// a host where the reads it enables actually succeed.
func fullyPrivileged() CapStatus {
	return CapStatus{
		HasBPF: true, HasPerfmon: true, HasSysAdmin: true,
		HasSysPtrace: true, HasDACReadSearch: true,
		FileCaps:            true,
		ProcSelfMemReadable: true,
		TracefsPath:         "/sys/kernel/tracing",
		TracefsReadable:     true,
		KernelMajor:         6, KernelMinor: 8,
		UnprivBPFDisabled: 2,
	}
}

// readmeSetcap is what the README taught before #117: enough to load, not
// enough to load everything.
func readmeSetcap() CapStatus {
	s := fullyPrivileged()
	s.HasSysAdmin = false
	s.HasDACReadSearch = false
	// The consequence of the missing CAP_DAC_READ_SEARCH, as the ADR measured
	// it: setcap made the process non-dumpable, so its own /proc/self/mem now
	// belongs to root, and tracefs is 0700 root:root.
	s.ProcSelfMemReadable = false
	return s
}

func outlookFor(t *testing.T, s CapStatus) map[string]CollectorOutlook {
	t.Helper()
	m := map[string]CollectorOutlook{}
	for _, o := range outlook(s, true) {
		m[o.Subsystem] = o
	}
	return m
}

func TestOutlookFullSetRunsEverything(t *testing.T) {
	for _, o := range outlook(fullyPrivileged(), true) {
		if !o.WillRun {
			t.Errorf("%s should run with the full capability set: %s", o.Subsystem, o.Blocker)
		}
	}
}

// The reported shape of #117: the README's setcap loads, and quietly leaves out
// every collector whose programs carry the kernel version — the two with a
// kprobe, AND the uprobe lanes, since SEC("uprobe/…") loads as
// BPF_PROG_TYPE_KPROBE and takes the same /proc/self/mem read.
func TestOutlookReadmeSetcapDropsTheVersionStampedCollectors(t *testing.T) {
	got := blockedCollectors(readmeSetcap(), true)
	sort.Strings(got)
	want := []string{"heap", "memory", "network", "tls"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("blocked = %v, want %v", got, want)
	}
	m := outlookFor(t, readmeSetcap())
	for _, name := range want {
		if !strings.Contains(m[name].Blocker, "CAP_DAC_READ_SEARCH") {
			t.Errorf("%s blocker should name CAP_DAC_READ_SEARCH: %q", name, m[name].Blocker)
		}
		if !strings.Contains(m[name].Blocker, "/proc/self/mem") {
			t.Errorf("%s blocker should name the read that failed: %q", name, m[name].Blocker)
		}
	}
	// memory keeps a /proc reader; network does not, and the difference is the
	// whole reason Degraded exists.
	if !m["memory"].Degraded {
		t.Error("memory has a /proc lane and should report as degraded, not gone")
	}
	if m["network"].Degraded {
		t.Error("network has no /proc lane; calling it degraded overstates what is left")
	}
}

// Verified on 7.0.0: with /proc/self/mem still unreadable, adding CAP_SYS_ADMIN
// buys nothing at all — heap fails at LOAD, before the uprobe PMU is reached.
// Anyone reading only the CAP_SYS_ADMIN half of #117 would grant exactly this
// and see no change, so it is pinned.
func TestOutlookSysAdminAloneRecoversNothing(t *testing.T) {
	s := readmeSetcap()
	s.HasSysAdmin = true
	got := blockedCollectors(s, true)
	sort.Strings(got)
	if want := "heap,memory,network,tls"; strings.Join(got, ",") != want {
		t.Fatalf("blocked = %v, want %v", got, want)
	}
}

// The other half: with the version read restored and only CAP_SYS_ADMIN
// missing, the uprobe PMU is what is left, and only the uprobe lanes go.
func TestOutlookDACAloneLeavesJustTheUprobePMU(t *testing.T) {
	s := readmeSetcap()
	s.HasDACReadSearch, s.ProcSelfMemReadable = true, true
	got := blockedCollectors(s, true)
	sort.Strings(got)
	if want := "heap,tls"; strings.Join(got, ",") != want {
		t.Fatalf("blocked = %v, want %v", got, want)
	}
	m := outlookFor(t, s)
	if !strings.Contains(m["heap"].Blocker, "CAP_SYS_ADMIN") {
		t.Errorf("heap blocker should name CAP_SYS_ADMIN: %q", m["heap"].Blocker)
	}
}

func TestOutlookUnreadableTracefsTakesOutEveryTracepointCollector(t *testing.T) {
	s := fullyPrivileged()
	s.TracefsReadable = false // everything else in place, so tracefs is the only fault
	m := outlookFor(t, s)
	for _, c := range ebpfCollectors {
		if c.how&attachTracepoint == 0 {
			continue
		}
		if m[c.name].WillRun {
			t.Errorf("%s attaches a tracepoint and should be blocked by an unreadable tracefs", c.name)
		}
	}
	// heap is uprobe-only: tracefs is not its problem.
	if !m["heap"].WillRun {
		t.Errorf("heap attaches no tracepoint; tracefs should not block it: %s", m["heap"].Blocker)
	}
}

// Not mounted and not readable are different problems with different fixes.
func TestOutlookDistinguishesUnmountedTracefs(t *testing.T) {
	s := fullyPrivileged()
	s.TracefsReadable, s.TracefsPath = false, ""
	m := outlookFor(t, s)
	if !strings.Contains(m["syscalls"].Blocker, "not mounted") {
		t.Errorf("blocker should say tracefs is not mounted: %q", m["syscalls"].Blocker)
	}
	if strings.Contains(m["syscalls"].Blocker, "CAP_DAC_READ_SEARCH") {
		t.Errorf("an unmounted tracefs is not a capability problem: %q", m["syscalls"].Blocker)
	}
}

func TestOutlookRootRunsEverything(t *testing.T) {
	s := CapStatus{
		IsRoot: true, ProcSelfMemReadable: true,
		TracefsPath: "/sys/kernel/tracing", TracefsReadable: true,
		KernelMajor: 6, KernelMinor: 8,
	}
	if blocked := blockedCollectors(s, true); len(blocked) != 0 {
		t.Errorf("root should run every collector, blocked: %v", blocked)
	}
}

func TestOutlookNoEBPFInBinary(t *testing.T) {
	m := map[string]CollectorOutlook{}
	for _, o := range outlook(fullyPrivileged(), false) {
		m[o.Subsystem] = o
	}
	if m["cpu"].WillRun {
		t.Error("a build with no eBPF programs runs no eBPF collector")
	}
	if !strings.Contains(m["cpu"].Blocker, "-tags=ebpf") {
		t.Errorf("blocker should name the build tag: %q", m["cpu"].Blocker)
	}
}

func TestStartupAdvisory(t *testing.T) {
	adv := startupAdvisory(readmeSetcap(), true, nil)
	for _, want := range []string{"heap", "memory", "network", "CAP_SYS_ADMIN", "CAP_DAC_READ_SEARCH", "--caps", RecommendedSetcap} {
		if !strings.Contains(adv, want) {
			t.Errorf("advisory does not mention %q:\n%s", want, adv)
		}
	}
	// The point of saying it at all: a dropped axis reads as a quiet target.
	if !strings.Contains(adv, "zeros") {
		t.Errorf("advisory should say what a dropped collector looks like downstream:\n%s", adv)
	}
}

// A capability that only blocks something the operator already switched off is
// not a gap; saying so every run is how a warning stops being read.
func TestStartupAdvisorySkipsWhatWasNotAskedFor(t *testing.T) {
	adv := startupAdvisory(readmeSetcap(), true, map[string]bool{"tls": true})
	if strings.Contains(adv, "tls") {
		t.Errorf("tls was not opted into; the advisory should not list it:\n%s", adv)
	}
	if !strings.Contains(adv, "heap") {
		t.Errorf("heap was still asked for and is still blocked:\n%s", adv)
	}

	// With every uprobe lane switched off, CAP_SYS_ADMIN gates nothing anyone
	// wanted and drops out of the message entirely.
	adv = startupAdvisory(readmeSetcap(), true, map[string]bool{"tls": true, "heap": true})
	if strings.Contains(adv, "CAP_SYS_ADMIN") {
		t.Errorf("CAP_SYS_ADMIN no longer gates anything requested:\n%s", adv)
	}
	if !strings.Contains(adv, "CAP_DAC_READ_SEARCH") {
		t.Errorf("memory and network are still blocked by it:\n%s", adv)
	}

	adv = startupAdvisory(readmeSetcap(), true,
		map[string]bool{"tls": true, "heap": true, "memory": true, "network": true})
	if adv != "" {
		t.Errorf("nothing requested is blocked; advisory should be empty:\n%s", adv)
	}
}

func TestStartupAdvisorySilentWhenNothingIsLost(t *testing.T) {
	if adv := startupAdvisory(fullyPrivileged(), true, nil); adv != "" {
		t.Errorf("nothing is blocked, advisory should be empty:\n%s", adv)
	}
	// A binary with no eBPF, or a process that cannot load any, already gets a
	// louder message; repeating it per collector is noise.
	if adv := startupAdvisory(fullyPrivileged(), false, nil); adv != "" {
		t.Errorf("no-eBPF build should not get a capability advisory:\n%s", adv)
	}
	if adv := startupAdvisory(CapStatus{KernelMajor: 6}, true, nil); adv != "" {
		t.Errorf("a process that cannot load BPF at all should not get this advisory:\n%s", adv)
	}
}

func TestCapReportNamesEveryGateAndTheFullGrant(t *testing.T) {
	out := readmeSetcap().CapReport()
	for _, want := range []string{
		"CAP_BPF", "CAP_PERFMON", "CAP_SYS_ADMIN", "CAP_DAC_READ_SEARCH", "CAP_SYS_PTRACE",
		"/proc/self/mem", "tracefs", RecommendedSetcap,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report does not mention %q:\n%s", want, out)
		}
	}
	// The non-obvious one has to be spelled out, not merely listed.
	if !strings.Contains(out, "non-dumpable") {
		t.Errorf("report should explain why setcap itself breaks /proc/self:\n%s", out)
	}
	if !strings.Contains(out, "root") || !strings.Contains(out, "deliberately") {
		t.Errorf("report should warn what CAP_SYS_ADMIN amounts to:\n%s", out)
	}
}

func TestGatesHeldFollowsRoot(t *testing.T) {
	for _, g := range (CapStatus{IsRoot: true}).Gates() {
		if !g.Held {
			t.Errorf("root holds %s", g.Cap)
		}
	}
	for _, g := range (CapStatus{}).Gates() {
		if g.Held {
			t.Errorf("an unprivileged process holds no %s", g.Cap)
		}
	}
}

// Every non-fatal gate must name the collectors it gates, and every gate must
// carry a mechanism: "permission denied" is exactly the message #117 is about.
func TestGatesCarryScopeAndMechanism(t *testing.T) {
	known := map[string]bool{}
	for _, c := range ebpfCollectors {
		known[c.name] = true
	}
	for _, g := range fullyPrivileged().Gates() {
		if g.Why == "" {
			t.Errorf("%s has no mechanism", g.Cap)
		}
		if g.Token == "" || !strings.Contains(RecommendedSetcap, g.Token) {
			t.Errorf("%s token %q is not in RecommendedSetcap", g.Cap, g.Token)
		}
		if g.Fatal {
			if len(g.Subsystems) != 0 {
				t.Errorf("%s gates everything; listing subsystems understates it", g.Cap)
			}
			continue
		}
		if len(g.Subsystems) == 0 {
			t.Errorf("%s is not fatal but names no subsystem it gates", g.Cap)
		}
		for _, name := range g.Subsystems {
			if !known[name] {
				t.Errorf("%s gates unknown subsystem %q", g.Cap, name)
			}
		}
	}
}

var secRE = regexp.MustCompile(`SEC\("(kprobe|kretprobe|uprobe|uretprobe|tracepoint)`)

// programToCollector maps a BPF object to the subsystem name --disable uses.
// Two objects feed heap: the libc allocator lane and the Go one.
var programToCollector = map[string]string{
	"cpu.bpf.c": "cpu", "threads.bpf.c": "threads", "memory.bpf.c": "memory",
	"io.bpf.c": "io", "network.bpf.c": "network", "syscalls.bpf.c": "syscalls",
	"futex.bpf.c": "futex", "security.bpf.c": "security", "proc.bpf.c": "lifecycle",
	"signal.bpf.c": "signals", "heap.bpf.c": "heap", "goalloc.bpf.c": "heap",
	"tls.bpf.c": "tls",
}

// The gate table is only as good as its claim about how each collector
// attaches, and that claim lives in the C. Read it back rather than trusting
// the comment: a new SEC("kprobe/...") in an existing program silently moves
// that collector under CAP_DAC_READ_SEARCH, and nothing else would notice.
func TestEBPFCollectorsMatchPrograms(t *testing.T) {
	files, err := filepath.Glob("programs/*.bpf.c")
	if err != nil || len(files) == 0 {
		t.Fatalf("no BPF programs found: %v", err)
	}
	fromSource := map[string]attachMechanism{}
	for _, f := range files {
		base := filepath.Base(f)
		name, ok := programToCollector[base]
		if !ok {
			t.Errorf("%s maps to no collector — add it to programToCollector and to ebpfCollectors", base)
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, m := range secRE.FindAllStringSubmatch(string(src), -1) {
			switch m[1] {
			case "tracepoint":
				fromSource[name] |= attachTracepoint
			case "kprobe", "kretprobe":
				fromSource[name] |= attachKprobe
			case "uprobe", "uretprobe":
				fromSource[name] |= attachUprobe
			}
		}
	}
	inTable := map[string]attachMechanism{}
	for _, c := range ebpfCollectors {
		if _, dup := inTable[c.name]; dup {
			t.Errorf("%s listed twice in ebpfCollectors", c.name)
		}
		inTable[c.name] = c.how
	}
	for name, how := range fromSource {
		if inTable[name] != how {
			t.Errorf("%s attaches %s in the C but %s in ebpfCollectors",
				name, mechanismString(how), mechanismString(inTable[name]))
		}
	}
	for name := range inTable {
		if _, ok := fromSource[name]; !ok {
			t.Errorf("ebpfCollectors lists %s, but no BPF program attaches for it", name)
		}
	}
}

func mechanismString(m attachMechanism) string {
	var parts []string
	if m&attachTracepoint != 0 {
		parts = append(parts, "tracepoint")
	}
	if m&attachKprobe != 0 {
		parts = append(parts, "kprobe")
	}
	if m&attachUprobe != 0 {
		parts = append(parts, "uprobe")
	}
	if len(parts) == 0 {
		return "nothing"
	}
	return strings.Join(parts, "+")
}
