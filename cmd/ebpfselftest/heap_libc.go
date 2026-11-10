//go:build linux && ebpf

package main

import (
	"bufio"
	_ "embed"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/trentas/ptop/internal/bpf"
	"github.com/trentas/ptop/pkg/collector"
)

// ─── heap: the libc lane, against a C program (#53, #109, #155) ─────────────

// libcHeapSource is the planted workload. This binary is static Go and has no
// libc to probe, so the target is a C program compiled at run time.
//
//go:embed testdata/libcheap.c
var libcHeapSource []byte

// What libcheap.c plants. Each value reaches the C program as a -D define, so
// the grader and the workload cannot disagree about it.
const (
	libcChurnPerTick = 100 // malloc+free pairs per 10ms tick: 10,000 a second
	libcChurnMs      = 4000
	libcChurnSize    = 4 << 10

	libcRetainMallocN    = 256
	libcRetainMallocSize = 16 << 10 // 4 MiB held

	libcRetainCallocN     = 128
	libcRetainCallocNmemb = 64
	libcRetainCallocSize  = 256 // calloc(64, 256): 16 KiB each, 2 MiB held

	libcGrowFrom = 1 << 10
	libcGrowTo   = 1 << 20 // realloc doubling from 1 KiB: 11 calls, 1 MiB held

	libcSpreadSites = 12
	libcSpreadN     = 64
	libcSpreadSize  = 4 << 10 // 256 KiB held per spread site
)

func libcDefines() []string {
	d := map[string]int{
		"CHURN_PER_TICK": libcChurnPerTick, "CHURN_MS": libcChurnMs, "CHURN_SIZE": libcChurnSize,
		"RETAIN_MALLOC_N": libcRetainMallocN, "RETAIN_MALLOC_SIZE": libcRetainMallocSize,
		"RETAIN_CALLOC_N": libcRetainCallocN, "RETAIN_CALLOC_NMEMB": libcRetainCallocNmemb,
		"RETAIN_CALLOC_SIZE": libcRetainCallocSize,
		"GROW_FROM":          libcGrowFrom, "GROW_TO": libcGrowTo,
		"SPREAD_N": libcSpreadN, "SPREAD_SIZE": libcSpreadSize,
	}
	out := make([]string, 0, len(d))
	for k, v := range d {
		out = append(out, fmt.Sprintf("-D%s=%d", k, v))
	}
	sort.Strings(out)
	return out
}

// libcGrowSteps is how many reallocs grow_realloc makes: 1 KiB, 2 KiB, … 1 MiB.
func libcGrowSteps() int {
	n := 0
	for s := libcGrowFrom; s <= libcGrowTo; s <<= 1 {
		n++
	}
	return n
}

// buildLibcWorkload compiles libcheap.c into dir. Frame pointers stay on and
// nothing is inlined or turned into a tail call, so each planted function is a
// frame of its own on the stack the probe walks.
//
// A host without a C compiler cannot take this case's readings, and that is a
// failure, not a skip: this case is the only grade the libc lane has, and a
// CI image that lost its compiler would otherwise pass it by vacuity.
func buildLibcWorkload(dir string) (string, error) {
	src := filepath.Join(dir, "libcheap.c")
	if err := os.WriteFile(src, libcHeapSource, 0o600); err != nil {
		return "", err
	}
	cc := ""
	for _, name := range []string{os.Getenv("CC"), "cc", "gcc", "clang"} {
		if name == "" {
			continue
		}
		if p, err := exec.LookPath(name); err == nil {
			cc = p
			break
		}
	}
	if cc == "" {
		return "", errors.New("no C compiler on PATH (tried $CC, cc, gcc, clang)")
	}
	bin := filepath.Join(dir, "libcheap")
	args := append([]string{
		"-O1", "-g", "-fno-builtin", "-fno-omit-frame-pointer", "-fno-inline", "-fno-optimize-sibling-calls",
		"-o", bin, src,
	}, libcDefines()...)
	if out, err := exec.Command(cc, args...).CombinedOutput(); err != nil {
		return "", fmt.Errorf("%s: %w: %s", filepath.Base(cc), err, strings.TrimSpace(string(out)))
	}
	return bin, nil
}

// checkLibcHeap grades the libc lane against libcheap.c. First a churn at a
// known rate, alone on the heap, so the churning site is the whole top list
// and its rate is the whole rate. Then blocks held at known sites, so the live
// bytes, the allocation counts and the census can be checked to the byte.
//
// The kernel aggregate behind the live bytes and the counts is exact for a
// heap this small (the LRU live set holds 131,072 blocks; this one peaks under
// 1,200), so every one of those is graded as an equality.
func checkLibcHeap(g *grader, _ int) {
	dir, err := os.MkdirTemp("", "ptop-selftest-heap-")
	if err != nil {
		g.broken("heap", "a scratch directory", err)
		return
	}
	defer os.RemoveAll(dir)
	bin, err := buildLibcWorkload(dir)
	if err != nil {
		g.broken("heap", "compile the C workload", err)
		return
	}

	cmd := exec.Command(bin)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		g.broken("heap", "the workload's stdin", err)
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		g.broken("heap", "the workload's stdout", err)
		return
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		g.broken("heap", "start the C workload", err)
		return
	}
	defer func() {
		_ = stdin.Close() // EOF: the workload exits
		_ = cmd.Wait()
	}()
	lines := bufio.NewReader(stdout)
	if l, err := lines.ReadString('\n'); err != nil || l != "ready\n" {
		g.broken("heap", "the workload's ready line", fmt.Errorf("got %q (%v)", l, err))
		return
	}

	var (
		start, churnEnd time.Time
		churned         uint64
		churnTook       time.Duration
		werr            error
	)
	c := collector.NewHeapEBPFCollector(bpf.GoAllocDefaultSampleBytes, nil) // the rate is the Go lane's; ignored here
	vals, err := collect(c, cmd.Process.Pid, 1200*time.Millisecond, func() {
		start = time.Now()
		if _, werr = stdin.Write([]byte{'g'}); werr != nil {
			return
		}
		var l string
		if l, werr = lines.ReadString('\n'); werr != nil {
			return
		}
		churnEnd = time.Now()
		f := strings.Fields(l)
		if len(f) != 3 || f[0] != "churned" {
			werr = fmt.Errorf("churn line %q", l)
			return
		}
		churned, _ = strconv.ParseUint(f[1], 10, 64)
		ns, _ := strconv.ParseInt(f[2], 10, 64)
		churnTook = time.Duration(ns)
		if l, werr = lines.ReadString('\n'); werr == nil && l != "retained\n" {
			werr = fmt.Errorf("retain line %q", l)
		}
	})
	if err != nil {
		g.broken("heap", "attach", err)
		return
	}
	if werr != nil {
		g.broken("heap", "drive the workload", werr)
		return
	}
	if churned == 0 || churnTook <= 0 {
		g.broken("heap", "the workload's churn report", fmt.Errorf("%d pairs in %v", churned, churnTook))
		return
	}

	var last, churnSnap collector.HeapStats
	var rates []float64
	for _, v := range vals {
		h, ok := v.(collector.HeapStats)
		if !ok {
			continue
		}
		last = h
		if !h.Timestamp.After(churnEnd) {
			churnSnap = h
		}
		// A window is (previous publish, this one]; only those wholly inside
		// the churn measure its rate.
		if h.Timestamp.After(start.Add(time.Second)) && !h.Timestamp.After(churnEnd) {
			rates = append(rates, h.AllocRate)
		}
	}
	if !g.check("heap", "the libc lane published, with live bytes measured",
		last.Lane == collector.HeapLaneLibc && last.LiveMeasured,
		"lane "+collector.HeapLaneLibc+", live measured",
		fmt.Sprintf("lane %q, live measured %v", last.Lane, last.LiveMeasured)) {
		return
	}

	// ── the churn, alone on the heap ──
	planted := float64(churned) / churnTook.Seconds()
	if g.check("heap", "windows wholly inside the churn", len(rates) >= 2, ">= 2", fmt.Sprint(len(rates))) {
		sort.Float64s(rates)
		med := rates[len(rates)/2]
		g.check("heap", "alloc rate (median window)", math.Abs(med-planted) <= planted*0.15,
			fmt.Sprintf("%.0f/s ±15%%", planted), fmt.Sprintf("%.0f/s", med))
	}
	churnSite, ok := siteNamed(churnSnap.TopCallSites, "churn_site")
	if g.check("heap", "the churning call site is named", ok, "churn_site", topFuncs(churnSnap.TopCallSites)) {
		// At most one block in flight, and each freed microseconds after it
		// was made.
		g.check("heap", "churn_site holds at most one block", churnSite.LiveBytes <= libcChurnSize,
			fmt.Sprintf("<= %d B", libcChurnSize), fmt.Sprintf("%d B", churnSite.LiveBytes))
		g.check("heap", "churn_site's mean lifetime", churnSite.AvgLifetimeMs > 0 && churnSite.AvgLifetimeMs < 1,
			"(0, 1ms)", fmt.Sprintf("%.3fms", churnSite.AvgLifetimeMs))
	}

	// ── the held blocks, to the byte ──
	want := []struct {
		fn    string
		bytes uint64
		count uint64
	}{
		{"retain_malloc", libcRetainMallocN * libcRetainMallocSize, libcRetainMallocN},
		{"retain_calloc", libcRetainCallocN * libcRetainCallocNmemb * libcRetainCallocSize, libcRetainCallocN},
		{"grow_realloc", libcGrowTo, uint64(libcGrowSteps())},
	}
	for _, w := range want {
		s, ok := siteNamed(last.TopCallSites, w.fn)
		if !g.check("heap", w.fn+" is named in the top list", ok, w.fn, topFuncs(last.TopCallSites)) {
			continue
		}
		g.check("heap", w.fn+" live bytes", s.LiveBytes == w.bytes,
			fmt.Sprintf("exactly %d B", w.bytes), fmt.Sprintf("%d B", s.LiveBytes))
		g.check("heap", w.fn+" allocations", s.AllocCount == w.count,
			fmt.Sprintf("exactly %d", w.count), fmt.Sprint(s.AllocCount))
	}

	// ── the census (#109) ──
	plantedLive := uint64(libcRetainMallocN*libcRetainMallocSize +
		libcRetainCallocN*libcRetainCallocNmemb*libcRetainCallocSize +
		libcGrowTo + libcSpreadSites*libcSpreadN*libcSpreadSize)
	g.check("heap", "live heap: the planted blocks and nothing else", last.LiveHeapBytes == plantedLive,
		fmt.Sprintf("exactly %d B", plantedLive), fmt.Sprintf("%d B", last.LiveHeapBytes))
	listed := uint32(len(last.TopCallSites))
	g.check("heap", fmt.Sprintf("spread over %d more call sites: the list was cut", libcSpreadSites),
		last.TotalCallSites > listed, fmt.Sprintf("more than %d sites", listed), fmt.Sprint(last.TotalCallSites))
	var listedLive, listedCount uint64
	for _, s := range last.TopCallSites {
		listedLive += s.LiveBytes
		listedCount += s.AllocCount
	}
	g.check("heap", "census: listed + omitted live bytes = the live heap",
		listedLive+last.OmittedLiveBytes == last.LiveHeapBytes,
		fmt.Sprintf("%d B", last.LiveHeapBytes),
		fmt.Sprintf("%d listed + %d omitted", listedLive, last.OmittedLiveBytes))
	plantedCount := churned + libcRetainMallocN + libcRetainCallocN + uint64(libcGrowSteps()) +
		libcSpreadSites*libcSpreadN
	g.check("heap", "census: listed + omitted allocations = every one planted",
		listedCount+last.OmittedAllocCount == plantedCount,
		fmt.Sprintf("exactly %d", plantedCount),
		fmt.Sprintf("%d listed + %d omitted", listedCount, last.OmittedAllocCount))
}

func siteNamed(sites []collector.HeapCallSite, fn string) (collector.HeapCallSite, bool) {
	for _, s := range sites {
		if s.Func == fn {
			return s, true
		}
	}
	return collector.HeapCallSite{}, false
}
