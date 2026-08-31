package collector

import (
	"sort"
	"strings"
	"testing"

	"github.com/trentas/ptop/internal/bpf"
)

// internal/bpf spells subsystem names as literals in its capability table
// (capgates.go): it cannot import this package, because this package imports
// it. That is fine as long as the two agree, and a divergence would be silent
// — `ptop --caps` would report on a collector nobody can name to --disable, or
// omit one that exists. These tests are the join the compiler cannot make.

func TestCapGateSubsystemsAreKnown(t *testing.T) {
	for _, g := range bpf.GetCapStatus().Gates() {
		for _, name := range g.Subsystems {
			if !knownSubsystems[name] {
				t.Errorf("%s claims to gate %q, which --disable does not know; known: %s",
					g.Cap, name, KnownSubsystems())
			}
		}
	}
}

func TestCapOutlookCoversEveryEBPFSubsystem(t *testing.T) {
	inOutlook := map[string]bool{}
	for _, o := range bpf.GetCapStatus().Outlook() {
		if !knownSubsystems[o.Subsystem] {
			t.Errorf("--caps reports on %q, which --disable does not know; known: %s",
				o.Subsystem, KnownSubsystems())
		}
		inOutlook[o.Subsystem] = true
	}
	// fd is the one subsystem that attaches nothing: it reads /proc/<pid>/fd
	// and needs no capability beyond being able to read it. Everything else
	// has an eBPF lane, so a missing name means a new collector nobody
	// answered the capability question for.
	var missing []string
	for name := range knownSubsystems {
		if name == SubsystemFD || inOutlook[name] {
			continue
		}
		missing = append(missing, name)
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("no capability gate answers for %s — add them to ebpfCollectors in internal/bpf/capgates.go",
			strings.Join(missing, ", "))
	}
}
