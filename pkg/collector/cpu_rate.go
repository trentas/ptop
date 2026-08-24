package collector

import "time"

// cpuPercent turns two readings of a monotonic on-CPU nanosecond counter into
// single-core percent — the top-style scale, where a target using two cores
// fully reads 200%, not 100%.
//
// Build-tag-free so the arithmetic is testable on any host; the counter it
// reads comes from the eBPF scheduler tracer (cpu_ebpf.go).
func cpuPercent(prevNs, curNs uint64, elapsed time.Duration, ncpu int) float64 {
	// A counter that went backwards means a slice ended between the two map
	// reads inside a single OnCPUNanos call (see its doc comment). Those
	// nanoseconds are not lost — they land in the next window — so report no
	// progress rather than a negative rate.
	if elapsed <= 0 || curNs < prevNs {
		return 0
	}
	pct := float64(curNs-prevNs) / float64(elapsed.Nanoseconds()) * 100
	// Saturate at every core running the target flat out. Nothing above that
	// is physical; it would mean the clock the counter is timestamped with
	// and the clock the interval is measured with disagree.
	if ncpu > 0 {
		if ceiling := float64(ncpu) * 100; pct > ceiling {
			return ceiling
		}
	}
	return pct
}
