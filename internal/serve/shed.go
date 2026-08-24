package serve

import pb "github.com/trentas/ptop/pkg/streampb"

// Fair shedding: how a sink decides what to drop when it cannot keep up (#108).
//
// A sink's queue is shared by every axis of the stream, and the axes do not
// arrive at remotely comparable rates. The periodic snapshots — CPU, memory,
// threads, locks, the heap aggregate — are one message each per tick, a handful
// per second between them. The per-occurrence events are emitted whenever the
// target does the thing, and one of them, the Go allocation probe, can emit
// hundreds of thousands per second.
//
// With one undifferentiated queue and drop-when-full, that ends in the flood
// owning the whole buffer: the CPU sample that comes once a second finds it
// full every time and is shed, over and over. What reaches the consumer is a
// stream with no CPU axis at all — and since the axis is missing rather than
// wrong, it reads as "the process used no CPU", which was the reported symptom:
// a 17-second window over a busy process whose CPU distribution was zero at
// every percentile.
//
// So the last quarter of every sink's queue is reserved for the snapshots. A
// flood can fill the first three quarters and no more; a once-a-second sample
// always finds room, unless the consumer has stopped reading altogether, in
// which case it is shed and counted like anything else.

// perOccurrenceLimit is how much of a sink's queue an unbounded-rate payload
// may occupy. The rest is reserved for the periodic snapshots.
const perOccurrenceLimit = subBuffer * 3 / 4

// isPerOccurrence reports whether an event is emitted once per thing the target
// did — as opposed to a periodic snapshot, which arrives on a timer at a rate
// the collector controls. Only the former can flood.
func isPerOccurrence(ev *pb.Event) bool {
	switch ev.GetPayload().(type) {
	case *pb.Event_HeapEvent, // one per allocation — the flood this exists for
		*pb.Event_FdEvent,
		*pb.Event_Timeline,
		*pb.Event_NetError,
		*pb.Event_FsEvent,
		*pb.Event_Signal,
		*pb.Event_Tls,
		*pb.Event_ProcLifecycle,
		*pb.Event_Security:
		return true
	default:
		// Snapshots: cpu, syscalls, network, memory, heap, threads, io_wait,
		// io_throughput, io, fds, locks, proc_context — and anything added
		// later, which is the safe default: a new payload is protected from
		// shedding rather than silently starved.
		return false
	}
}

// admits reports whether a queue holding qlen items should take ev, given a
// capacity of subBuffer. Snapshots use the whole queue; per-occurrence events
// stop at the reserve.
func admits(qlen int, ev *pb.Event) bool {
	if isPerOccurrence(ev) {
		return qlen < perOccurrenceLimit
	}
	return true
}
