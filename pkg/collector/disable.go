package collector

import (
	"fmt"
	"sort"
	"strings"
)

// Turning individual subsystems off.
//
// Every collector has a cost, and they are not remotely equal. A tracepoint
// fires when the kernel reaches it; a uprobe on the allocator fires as often
// as the target allocates, which on a busy service is orders of magnitude more
// often than anything else ptop attaches. An operator watching a hot allocator
// may well want everything EXCEPT that, and until now the only choices were
// all of it or --no-ebpf.
//
// It is also what makes the overhead question answerable. "ptop costs N%" is
// not a fact about ptop, it is a fact about ptop's most expensive probe on one
// workload; measuring with and without a named subsystem is the only way to
// say which part the N% actually is.

// Subsystem names accepted by SetConfig.Disable. They match the names in
// ptop's own warnings, so a message about a subsystem tells you what to pass
// to switch it off.
const (
	SubsystemCPU       = "cpu"
	SubsystemThreads   = "threads"
	SubsystemMemory    = "memory"
	SubsystemHeap      = "heap"
	SubsystemSyscalls  = "syscalls"
	SubsystemIO        = "io"
	SubsystemNetwork   = "network"
	SubsystemFutex     = "futex"
	SubsystemSignals   = "signals"
	SubsystemLifecycle = "lifecycle"
	SubsystemSecurity  = "security"
	SubsystemTLS       = "tls"
	SubsystemFD        = "fd"
)

// knownSubsystems is the full set, used to reject a typo rather than let it
// silently disable nothing — the failure mode of a misspelled --disable is a
// benchmark that measures the wrong configuration and reports it confidently.
var knownSubsystems = map[string]bool{
	SubsystemCPU: true, SubsystemThreads: true, SubsystemMemory: true,
	SubsystemHeap: true, SubsystemSyscalls: true, SubsystemIO: true,
	SubsystemNetwork: true, SubsystemFutex: true, SubsystemSignals: true,
	SubsystemLifecycle: true, SubsystemSecurity: true, SubsystemTLS: true,
	SubsystemFD: true,
}

// ParseDisable turns a comma-separated subsystem list into the set
// SetConfig.Disable takes. An empty or whitespace-only string yields nil.
//
// An unknown name is an error, not a warning: the whole point of the flag is
// to be sure which probes are running.
func ParseDisable(spec string) (map[string]bool, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	out := make(map[string]bool)
	for _, raw := range strings.Split(spec, ",") {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		if !knownSubsystems[name] {
			return nil, fmt.Errorf("unknown subsystem %q; known: %s", name, KnownSubsystems())
		}
		out[name] = true
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// KnownSubsystems lists every accepted name, sorted, for help text and errors.
func KnownSubsystems() string {
	names := make([]string, 0, len(knownSubsystems))
	for n := range knownSubsystems {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// off reports whether a subsystem was disabled.
func (cfg SetConfig) off(name string) bool { return cfg.Disable[name] }
