package serve

import (
	"testing"

	pb "github.com/trentas/ptop/pkg/streampb"
)

func cpuEvent() *pb.Event {
	return &pb.Event{
		Category: pb.Category_CATEGORY_CPU,
		Payload:  &pb.Event_Cpu{Cpu: &pb.CpuSample{UsagePct: 42}},
	}
}

func allocEvent() *pb.Event {
	return &pb.Event{
		Category: pb.Category_CATEGORY_MEMORY,
		Payload:  &pb.Event_HeapEvent{HeapEvent: &pb.HeapEvent{Op: "alloc", Size: 64}},
	}
}

func TestIsPerOccurrence(t *testing.T) {
	perOccurrence := []*pb.Event{
		allocEvent(),
		{Payload: &pb.Event_FdEvent{FdEvent: &pb.FdEvent{}}},
		{Payload: &pb.Event_Timeline{Timeline: &pb.TimelineEvent{}}},
		{Payload: &pb.Event_NetError{NetError: &pb.NetErrorEvent{}}},
		{Payload: &pb.Event_FsEvent{FsEvent: &pb.FSEvent{}}},
		{Payload: &pb.Event_Signal{Signal: &pb.SignalEvent{}}},
		{Payload: &pb.Event_Tls{Tls: &pb.TLSPayloadEvent{}}},
		{Payload: &pb.Event_ProcLifecycle{ProcLifecycle: &pb.ProcLifecycleEvent{}}},
		{Payload: &pb.Event_Security{Security: &pb.SecurityEvent{}}},
	}
	for _, ev := range perOccurrence {
		if !isPerOccurrence(ev) {
			t.Errorf("%T: isPerOccurrence = false, want true", ev.GetPayload())
		}
	}

	snapshots := []*pb.Event{
		cpuEvent(),
		{Payload: &pb.Event_Memory{Memory: &pb.MemStats{}}},
		{Payload: &pb.Event_Heap{Heap: &pb.HeapSnapshot{}}},
		{Payload: &pb.Event_Threads{Threads: &pb.ThreadSnapshot{}}},
		{Payload: &pb.Event_Locks{Locks: &pb.LockSnapshot{}}},
		{Payload: &pb.Event_Syscalls{Syscalls: &pb.SyscallSnapshot{}}},
		{Payload: &pb.Event_Network{Network: &pb.NetworkSnapshot{}}},
		{Payload: &pb.Event_Fds{Fds: &pb.FdSnapshot{}}},
		{Payload: &pb.Event_Io{Io: &pb.IoSnapshot{}}},
		{Payload: &pb.Event_IoWait{IoWait: &pb.IoWaitSample{}}},
		{Payload: &pb.Event_IoThroughput{IoThroughput: &pb.IoThroughputSample{}}},
		{Payload: &pb.Event_ProcContext{ProcContext: &pb.ProcContext{}}},
		{}, // no payload at all: protected, not starved
	}
	for _, ev := range snapshots {
		if isPerOccurrence(ev) {
			t.Errorf("%T: isPerOccurrence = true, want false", ev.GetPayload())
		}
	}
}

func TestAdmitsReservesRoomForSnapshots(t *testing.T) {
	cases := []struct {
		qlen        int
		alloc, snap bool
	}{
		{0, true, true},
		{perOccurrenceLimit - 1, true, true},
		{perOccurrenceLimit, false, true}, // the reserve begins
		{subBuffer - 1, false, true},      // last slot still open to a snapshot
	}
	for _, tc := range cases {
		if got := admits(tc.qlen, allocEvent()); got != tc.alloc {
			t.Errorf("qlen=%d: admits(alloc) = %v, want %v", tc.qlen, got, tc.alloc)
		}
		if got := admits(tc.qlen, cpuEvent()); got != tc.snap {
			t.Errorf("qlen=%d: admits(cpu) = %v, want %v", tc.qlen, got, tc.snap)
		}
	}
}

// The reported failure (#108): a consumer that cannot keep up with a flood of
// per-allocation events still has to see the once-a-second CPU sample. Before
// the reserve the flood owned the whole queue and the CPU axis came out empty,
// which reads as a process that used no CPU.
func TestSinkFloodDoesNotStarveTheCPUAxis(t *testing.T) {
	s := newGRPCSink(nil)

	for i := 0; i < subBuffer*4; i++ { // a consumer reading nothing
		s.Emit(allocEvent())
	}
	s.Emit(cpuEvent())

	var cpu, alloc int
	for {
		select {
		case resp := <-s.ch:
			if isPerOccurrence(resp.GetEvent()) {
				alloc++
			} else {
				cpu++
			}
			continue
		default:
		}
		break
	}
	if cpu != 1 {
		t.Errorf("CPU samples delivered = %d, want 1 (the flood starved the axis)", cpu)
	}
	if alloc != perOccurrenceLimit {
		t.Errorf("per-occurrence events queued = %d, want the limit %d", alloc, perOccurrenceLimit)
	}
	if s.dropped == 0 {
		t.Error("shed events were not counted; a gap must always be reported")
	}
}
