//go:build linux && ebpf

package main

import (
	"fmt"
	"os"
	"strings"
)

// Every reading the selftest takes is graded against a value it knew before it
// measured, and every grade prints the same way: the axis, the claim, what was
// expected and what was measured (#155). A failure then names the axis and the
// size of the miss. "0 events" says neither.
//
// The discipline is the one from Gregg's "Performance Prompts" grading (slides
// 40-42): the best-scoring agent there was invalid, because it raised the score
// without being right. A grader that checks that SOMETHING was emitted is
// gameable the same way, by any axis that emits the wrong thing.
type grader struct {
	passed, failed, skipped int
}

// check records one graded reading. want and got are prose, already formatted
// by the caller with the units and the tolerance the claim is judged by.
func (g *grader) check(axis, claim string, ok bool, want, got string) bool {
	if ok {
		g.passed++
		fmt.Printf("PASS  %-9s %s: want %s, got %s\n", axis, claim, want, got)
		return true
	}
	g.failed++
	fmt.Fprintf(os.Stderr, "FAIL  %-9s %s: want %s, got %s\n", axis, claim, want, got)
	return false
}

// broken records a case that could not take its reading at all — an attach
// that failed, a workload that would not start. That is a failure, never a
// skip: an axis that cannot be graded is not one that passed.
func (g *grader) broken(axis, claim string, err error) {
	g.failed++
	fmt.Fprintf(os.Stderr, "FAIL  %-9s %s: %v\n", axis, claim, err)
}

// skip records a claim this host cannot test, with the reason. Only for a
// condition of the HOST (no cgroup subtree to target, a kernel without the
// lane), never for a failure of the code under test.
func (g *grader) skip(axis, claim, why string) {
	g.skipped++
	fmt.Printf("SKIP  %-9s %s: %s\n", axis, claim, why)
}

// note prints context that is reported rather than asserted, aligned under
// the graded lines.
func (g *grader) note(axis, format string, a ...any) {
	fmt.Printf("      %-9s "+format+"\n", append([]any{axis}, a...)...)
}

func (g *grader) summary() string {
	return fmt.Sprintf("%d passed, %d failed, %d skipped", g.passed, g.failed, g.skipped)
}

// selfCase is one axis of the suite: a workload whose answer is known, and the
// grades taken against it.
type selfCase struct {
	name string // what -run selects it by
	what string // one line for -list
	run  func(g *grader, pid int)
}

// selectCases resolves -run. An unknown name is an error rather than a case
// silently not run: a suite that selected nothing would pass by vacuity.
func selectCases(all []selfCase, spec string) ([]selfCase, error) {
	if spec == "" {
		return all, nil
	}
	byName := make(map[string]selfCase, len(all))
	for _, c := range all {
		byName[c.name] = c
	}
	want := make(map[string]bool)
	for _, name := range strings.Split(spec, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := byName[name]; !ok {
			return nil, fmt.Errorf("-run: no case named %q (have: %s)", name, caseNames(all))
		}
		want[name] = true
	}
	if len(want) == 0 {
		return nil, fmt.Errorf("-run %q selects no case (have: %s)", spec, caseNames(all))
	}
	// Keep the suite's own order: later cases may assume an earlier one's
	// failure was already reported (the filter before the accuracy built on it).
	var out []selfCase
	for _, c := range all {
		if want[c.name] {
			out = append(out, c)
		}
	}
	return out, nil
}

func caseNames(all []selfCase) string {
	names := make([]string, len(all))
	for i, c := range all {
		names[i] = c.name
	}
	return strings.Join(names, ", ")
}
