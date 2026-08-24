package collector

// Fair shedding on the bus: which value a full subscription queue gives up
// (#108). internal/serve does the same thing one layer down, on the mapped
// stream events; the reasoning is written out there.
//
// The short version: the axes do not arrive at comparable rates. A periodic
// snapshot is one value per tick; a per-occurrence event is one value per thing
// the target did, and the Go allocation probe can emit hundreds of thousands a
// second. Drop-when-full then means the flood owns the queue and the
// once-a-second CpuSample never fits — the consumer ends up with no CPU axis
// at all, which reads as an idle process rather than as a gap.

// perOccurrenceLimitOf is the share of a queue of size n that an
// unbounded-rate value may occupy; the rest is reserved for snapshots.
func perOccurrenceLimitOf(n int) int {
	if lim := n * 3 / 4; lim > 0 {
		return lim
	}
	return 1 // a queue this small has nothing to reserve
}

// isPerOccurrenceValue reports whether a published value is emitted once per
// thing the target did, rather than on the collector's own timer. Only these
// can flood, so only these are held back from the reserve.
func isPerOccurrenceValue(v interface{}) bool {
	switch v.(type) {
	case HeapEvent, // one per allocation — the flood this exists for
		FDEvent,
		TimelineEvent,
		NetError,
		FSEvent,
		SignalEvent,
		TLSPayload,
		ProcLifecycleEvent,
		SecurityEvent:
		return true
	default:
		// Snapshots — CpuSample, MemStats, HeapStats, []ThreadInfo,
		// []LockEntry, []NetConn, []FDEntry, IOWaitSample,
		// IOThroughputSample, IOEBPFSnapshot, ProcContext, syscall counts —
		// and anything added later, which is the safe default: a new value is
		// protected from shedding rather than silently starved.
		return false
	}
}
