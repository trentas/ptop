package bpf

// ProbeCostCounters mirrors `struct probe_cost` in programs/probecost.bpf.h,
// summed over CPUs: a heap probe's hits since it attached, and the program
// time of the hits it timed (one in 64). See #154.
type ProbeCostCounters struct {
	Entries uint64 // uprobe hits
	Returns uint64 // uretprobe hits
	Timed   uint64 // hits whose program time was measured
	TimedNs uint64 // their program time
}

func sumProbeCost(perCPU []ProbeCostCounters) ProbeCostCounters {
	var out ProbeCostCounters
	for _, c := range perCPU {
		out.Entries += c.Entries
		out.Returns += c.Returns
		out.Timed += c.Timed
		out.TimedNs += c.TimedNs
	}
	return out
}
