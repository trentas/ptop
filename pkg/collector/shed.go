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

// publish offers v on a collector's own output channel, applying the same
// reserve the bus applies one layer up (#121).
//
// This hop was the one place the policy was missing, and it is the first one a
// value passes: a collector that emits both classes writes them to ONE channel,
// so `select { case ch <- v: default: }` lets the flood own all 64 slots and the
// collector's own timer-driven snapshot — built correctly, out of the kernel
// aggregate — is thrown away on the way out. Measured on a C target allocating
// ~700k times a second: every heap snapshot carried a call site and an alloc
// rate, and roughly half never left the collector, with the survivors starved
// again downstream. What reached the consumer was a heap axis of zeros, which
// reads as a process that did not allocate.
//
// Returns false when v was shed, so a caller that counts drops can.
func publish(ch chan interface{}, v interface{}) bool {
	if isPerOccurrenceValue(v) && len(ch) >= perOccurrenceLimitOf(cap(ch)) {
		return false
	}
	select {
	case ch <- v:
		return true
	default:
		return false
	}
}

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
