package bpf

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The eBPF objects are embedded per architecture (#123), which means three
// places have to agree: the .bpf.c sources, and the amd64 and arm64 embed
// files. Adding a program and updating only one of them produces a binary that
// builds on the author's machine and fails to compile on the other
// architecture — or, worse, a release where one architecture silently carries
// fewer probes than the other.
//
// Build-tag-free on purpose: this reads the files as text, so it runs on every
// host including the macOS port, where neither embed file compiles.

var embedRE = regexp.MustCompile(`//go:embed programs/obj/(\w+)/(\S+\.bpf\.o)\nvar (\w+) \[\]byte`)

type embedded struct {
	objects map[string]string // object file -> var name
	arch    string
}

func readEmbeds(t *testing.T, arch string) embedded {
	t.Helper()
	path := "objects_" + arch + ".go"
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	out := embedded{objects: map[string]string{}, arch: arch}
	for _, m := range embedRE.FindAllStringSubmatch(string(src), -1) {
		dir, obj, name := m[1], m[2], m[3]
		if dir != arch {
			t.Errorf("%s embeds %s from programs/obj/%s — an object built for another architecture", path, obj, dir)
		}
		if prev, dup := out.objects[obj]; dup {
			t.Errorf("%s embeds %s twice (%s, %s)", path, obj, prev, name)
		}
		out.objects[obj] = name
	}
	if len(out.objects) == 0 {
		t.Fatalf("%s embeds nothing — the regexp or the file shape changed", path)
	}
	return out
}

func TestEachArchEmbedsEveryProgram(t *testing.T) {
	sources, err := filepath.Glob("programs/*.bpf.c")
	if err != nil || len(sources) == 0 {
		t.Fatalf("no .bpf.c sources found: %v", err)
	}
	want := make([]string, 0, len(sources))
	for _, s := range sources {
		want = append(want, strings.TrimSuffix(filepath.Base(s), ".c")+".o")
	}
	sort.Strings(want)

	for _, arch := range []string{"amd64", "arm64"} {
		e := readEmbeds(t, arch)
		got := make([]string, 0, len(e.objects))
		for obj := range e.objects {
			got = append(got, obj)
		}
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("objects_%s.go embeds %v, but programs/ has %v", arch, got, want)
		}
	}
}

// The two architectures must bind the same object to the same variable, or a
// loader would reach for a program that only exists on one of them.
func TestArchEmbedsAgreeOnVariables(t *testing.T) {
	a := readEmbeds(t, "amd64")
	b := readEmbeds(t, "arm64")
	for obj, va := range a.objects {
		vb, ok := b.objects[obj]
		if !ok {
			t.Errorf("%s is embedded for amd64 but not arm64", obj)
			continue
		}
		if va != vb {
			t.Errorf("%s binds %s on amd64 and %s on arm64", obj, va, vb)
		}
	}
	for obj := range b.objects {
		if _, ok := a.objects[obj]; !ok {
			t.Errorf("%s is embedded for arm64 but not amd64", obj)
		}
	}
}

// The fallback file must declare every variable too, so an unsupported
// architecture fails to LOAD rather than failing to COMPILE — and must embed
// nothing, since a wrong-architecture object is worse than a missing one.
func TestOtherArchDeclaresEveryVariableAndEmbedsNothing(t *testing.T) {
	src, err := os.ReadFile("objects_other.go")
	if err != nil {
		t.Fatalf("read objects_other.go: %v", err)
	}
	if strings.Contains(string(src), "//go:embed") {
		t.Error("objects_other.go embeds an object; an unsupported arch must carry none")
	}
	for obj, name := range readEmbeds(t, "amd64").objects {
		if !strings.Contains(string(src), "var "+name+" []byte") {
			t.Errorf("objects_other.go does not declare %s (for %s)", name, obj)
		}
	}
}
