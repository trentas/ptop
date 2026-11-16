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
	"strconv"
	"strings"
	"time"

	"github.com/trentas/ptop/internal/bpf"
	"github.com/trentas/ptop/pkg/collector"
)

// ─── jvmpause: a HotSpot JVM's safepoints and collections (#189) ────────────

// jvmPlantSource is the planted workload: a Java program, run in source-file
// mode, that forces full collections and reports what the JVM itself counted.
//
//go:embed testdata/JvmPlant.java
var jvmPlantSource []byte

const (
	jvmPlantCycles = 20
	// 1M live arrays of four longs: a full collection traces and moves ~48 MB,
	// a few milliseconds a cycle, against a 256 MB heap nothing else fills.
	jvmPlantObjects = 1_000_000
)

// findJava returns $JAVA_HOME/bin/java, else java on PATH.
//
// A host without a JDK cannot take this case's readings, and that is a
// failure, not a skip, for the reason a missing C compiler fails the heap
// case: this is the only grade the JVM lane has.
func findJava() (string, error) {
	if h := os.Getenv("JAVA_HOME"); h != "" {
		p := filepath.Join(h, "bin", "java")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	if p, err := exec.LookPath("java"); err == nil {
		return p, nil
	}
	return "", errors.New("no JDK: neither $JAVA_HOME/bin/java nor java on PATH (sudo resets both; run it as `sudo env JAVA_HOME=$JAVA_HOME …`)")
}

// checkJVMPauses grades the JVM pause axis against collections planted in a
// real HotSpot JVM. System.gc() under G1 is one full collection, and one
// safepoint, per call; the program allocates nothing else in the window and
// reports the JVM's own census of it: its safepoint count and time (HotSpot's
// sun.rt counters) and its collections (the GC MXBeans). Both lanes are graded
// against those, and the collections against the program's own clock around
// each System.gc(), which contains them.
//
// Then this process: a Go program, not a JVM, which must be unsupported.
func checkJVMPauses(g *grader, self int) {
	if _, err := bpf.OpenJVMPauseTracer(self); errors.Is(err, bpf.ErrNotJVM) {
		g.check("jvmpause", "a target that is not a JVM is unsupported", true, "ErrNotJVM", "ErrNotJVM")
	} else {
		got := "attached"
		if err != nil {
			got = err.Error()
		}
		g.check("jvmpause", "a target that is not a JVM is unsupported", false, "ErrNotJVM", got)
	}

	java, err := findJava()
	if err != nil {
		g.broken("jvmpause", "find a JDK", err)
		return
	}
	dir, err := os.MkdirTemp("", "ptop-selftest-jvm-")
	if err != nil {
		g.broken("jvmpause", "a scratch directory", err)
		return
	}
	defer os.RemoveAll(dir)
	src := filepath.Join(dir, "JvmPlant.java")
	if err := os.WriteFile(src, jvmPlantSource, 0o600); err != nil {
		g.broken("jvmpause", "write the Java workload", err)
		return
	}

	cmd := exec.Command(java,
		"-XX:+UseG1GC", "-Xms256m", "-Xmx256m",
		// VM warnings go to stderr, so stdout carries the protocol alone.
		"-XX:+DisplayVMOutputToStderr",
		"--add-exports", "java.management/sun.management=ALL-UNNAMED",
		src, strconv.Itoa(jvmPlantCycles), strconv.Itoa(jvmPlantObjects), strconv.FormatInt(time.Now().UnixNano(), 10))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		g.broken("jvmpause", "the JVM's stdin", err)
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		g.broken("jvmpause", "the JVM's stdout", err)
		return
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		g.broken("jvmpause", "start the JVM", err)
		return
	}
	defer func() {
		_ = stdin.Close() // EOF: the workload exits
		exited := make(chan struct{})
		go func() { _ = cmd.Wait(); close(exited) }()
		select {
		case <-exited:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
	}()
	lines := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	readLine := func(prefix string, timeout time.Duration) (string, error) {
		deadline := time.After(timeout)
		for {
			select {
			case l, ok := <-lines:
				if !ok {
					return "", fmt.Errorf("the JVM exited before a %q line", prefix)
				}
				if strings.HasPrefix(l, prefix) {
					return l, nil
				}
				g.note("jvmpause", "jvm: %s", l)
			case <-deadline:
				return "", fmt.Errorf("no %q line in %v", prefix, timeout)
			}
		}
	}
	// Source-file mode compiles the program first: seconds on a slow runner.
	if _, err := readLine("ready", 90*time.Second); err != nil {
		g.broken("jvmpause", "the JVM's ready line", err)
		return
	}

	c := collector.NewJVMPauseEBPFCollector()
	if err := c.Start(cmd.Process.Pid); err != nil {
		g.broken("jvmpause", "attach to the JVM", err)
		return
	}
	defer c.Stop()
	// The JDK this runs on carries both lanes; one missing here is that lane's
	// only grade gone, so it fails rather than grading what is left.
	g.check("jvmpause", "both lanes attach (safepoints and gc)", c.Caveat() == "", "no caveat", strconv.Quote(c.Caveat()))

	ch := c.Subscribe()
	sample := func(after time.Time) (collector.JVMPauses, error) {
		deadline := time.After(5 * time.Second)
		for {
			select {
			case v := <-ch:
				if p, ok := v.(collector.JVMPauses); ok && p.Timestamp.After(after) {
					return p, nil
				}
			case <-deadline:
				return collector.JVMPauses{}, errors.New("no JVMPauses sample in 5s")
			}
		}
	}
	// The baseline is a reading taken before the plant starts, so the window's
	// difference holds the planted pauses and only those.
	first, err := sample(time.Time{})
	if err != nil {
		g.broken("jvmpause", "a baseline reading", err)
		return
	}
	if _, err := stdin.Write([]byte("go\n")); err != nil {
		g.broken("jvmpause", "start the plant", err)
		return
	}
	l, err := readLine("done", 60*time.Second)
	if err != nil {
		g.broken("jvmpause", "the JVM's done line", err)
		return
	}
	last, err := sample(time.Now())
	if err != nil {
		g.broken("jvmpause", "a reading after the plant", err)
		return
	}
	var jvmSafepoints, jvmSafepointMs, jvmCollections, gcWallNs uint64
	if _, err := fmt.Sscanf(l, "done %d %d %d %d", &jvmSafepoints, &jvmSafepointMs, &jvmCollections, &gcWallNs); err != nil {
		g.broken("jvmpause", "the JVM's done line", fmt.Errorf("%q: %w", l, err))
		return
	}
	if jvmCollections < jvmPlantCycles {
		g.broken("jvmpause", "the plant", fmt.Errorf("the JVM counted %d collections for %d System.gc()", jvmCollections, jvmPlantCycles))
		return
	}
	if first.Safepoints == nil || last.Safepoints == nil || first.GC == nil || last.GC == nil {
		g.check("jvmpause", "both lanes publish", false, "safepoints and gc", fmt.Sprintf("%+v", last))
		return
	}

	sp := diffPauses(first.Safepoints, last.Safepoints)
	gc := diffPauses(first.GC, last.GC)
	g.note("jvmpause", "the JVM counted %d safepoints, %d ms, %d collections; System.gc() took %v",
		jvmSafepoints, jvmSafepointMs, jvmCollections, time.Duration(gcWallNs).Round(time.Microsecond))

	// Collections: exact. Every one the JVM's MXBeans counted, and no other.
	g.check("jvmpause", fmt.Sprintf("collections for %d forced full GCs", jvmPlantCycles),
		gc.Count == jvmCollections, fmt.Sprintf("%d (the JVM's own count)", jvmCollections), fmt.Sprint(gc.Count))
	// Safepoints: the JVM's count over its own span, which sits inside ours by
	// the two short idle gaps on either side of the plant, so a stray cleanup
	// safepoint there is the only difference allowed.
	g.check("jvmpause", "safepoints in the window",
		sp.Count >= jvmSafepoints && sp.Count <= jvmSafepoints+2,
		fmt.Sprintf("%d (the JVM's own count), at most 2 more", jvmSafepoints), fmt.Sprint(sp.Count))
	// Their time, against the JVM's own: it accumulates whole milliseconds per
	// counter read, two counters, two reads.
	jvmNs := float64(jvmSafepointMs) * 1e6
	tol := 2e6 + 0.05*jvmNs
	g.check("jvmpause", "time stopped at safepoints",
		math.Abs(float64(sp.SumNs)-jvmNs) <= tol,
		fmt.Sprintf("%d ms (the JVM's own) ± %.1f ms", jvmSafepointMs, tol/1e6),
		fmt.Sprintf("%.1f ms", float64(sp.SumNs)/1e6))
	// A collection lies inside a safepoint, and inside the System.gc() call
	// that asked for it; with a live set this size it is most of that call.
	g.check("jvmpause", "collections inside the safepoints", gc.SumNs <= sp.SumNs,
		fmt.Sprintf("<= %.1f ms", float64(sp.SumNs)/1e6), fmt.Sprintf("%.1f ms", float64(gc.SumNs)/1e6))
	g.check("jvmpause", "collections inside the program's own clock around System.gc()",
		gc.SumNs <= gcWallNs && gc.SumNs >= gcWallNs/2,
		fmt.Sprintf("(50%%, 100%%] of %.1f ms", float64(gcWallNs)/1e6), fmt.Sprintf("%.1f ms", float64(gc.SumNs)/1e6))
	g.check("jvmpause", "every safepoint in exactly one bucket", sp.bucketed == sp.Count, fmt.Sprint(sp.Count), fmt.Sprint(sp.bucketed))
	g.check("jvmpause", "every collection in exactly one bucket", gc.bucketed == gc.Count, fmt.Sprint(gc.Count), fmt.Sprint(gc.bucketed))
}

type pauseDiff struct {
	Count, SumNs, bucketed uint64
}

func diffPauses(a, b *collector.PauseHistogram) pauseDiff {
	d := pauseDiff{Count: b.Count - a.Count, SumNs: b.SumNs - a.SumNs}
	for i := range b.Buckets {
		if i < len(a.Buckets) {
			d.bucketed += b.Buckets[i] - a.Buckets[i]
		}
	}
	return d
}
