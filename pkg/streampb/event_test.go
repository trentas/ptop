package streampb

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

// Round-trip an Event through proto marshal/unmarshal to prove the generated
// bindings link and the envelope + a representative oneof arm survive the wire.
func TestEventRoundTrip(t *testing.T) {
	orig := &Event{
		TsUnixNano: 1_700_000_000_000_000_000,
		Pid:        4242,
		Tid:        4243,
		Category:   Category_CATEGORY_CPU,
		Stack:      &StackRef{StackId: 7, BuildId: "abc123"},
		Payload:    &Event_Cpu{Cpu: &CpuSample{UsagePct: 73.5}},
	}

	wire, err := proto.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got := &Event{}
	if err := proto.Unmarshal(wire, got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !proto.Equal(orig, got) {
		t.Fatalf("round-trip mismatch:\n orig = %v\n got  = %v", orig, got)
	}
	if got.GetCpu().GetUsagePct() != 73.5 {
		t.Errorf("cpu usage = %v, want 73.5", got.GetCpu().GetUsagePct())
	}
	if got.GetStack().GetStackId() != 7 {
		t.Errorf("stack id = %v, want 7", got.GetStack().GetStackId())
	}
}

// Each oneof arm marshals and reads back through the typed getter — guards the
// payload wiring across every category as the schema grows.
func TestEventPayloadArms(t *testing.T) {
	cases := []struct {
		name    string
		payload isEvent_Payload
		check   func(*Event) bool
	}{
		{"cpu", &Event_Cpu{Cpu: &CpuSample{UsagePct: 1}}, func(e *Event) bool { return e.GetCpu() != nil }},
		{"syscalls", &Event_Syscalls{Syscalls: &SyscallSnapshot{Stats: []*SyscallStat{{Name: "read", Count: 2}}}}, func(e *Event) bool { return len(e.GetSyscalls().GetStats()) == 1 }},
		{"network", &Event_Network{Network: &NetworkSnapshot{Conns: []*NetConn{{Fd: 3}}}}, func(e *Event) bool { return len(e.GetNetwork().GetConns()) == 1 }},
		{"memory", &Event_Memory{Memory: &MemStats{RssBytes: 4}}, func(e *Event) bool { return e.GetMemory().GetRssBytes() == 4 }},
		{"threads", &Event_Threads{Threads: &ThreadSnapshot{Threads: []*ThreadInfo{{Tid: 5}}}}, func(e *Event) bool { return len(e.GetThreads().GetThreads()) == 1 }},
		{"io_wait", &Event_IoWait{IoWait: &IoWaitSample{Pct: 6}}, func(e *Event) bool { return e.GetIoWait().GetPct() == 6 }},
		{"io_throughput", &Event_IoThroughput{IoThroughput: &IoThroughputSample{ReadOps: 7}}, func(e *Event) bool { return e.GetIoThroughput().GetReadOps() == 7 }},
		{"io", &Event_Io{Io: &IoSnapshot{Opens: 8}}, func(e *Event) bool { return e.GetIo().GetOpens() == 8 }},
		{"fds", &Event_Fds{Fds: &FdSnapshot{Fds: []*FdEntry{{Fd: 9}}}}, func(e *Event) bool { return len(e.GetFds().GetFds()) == 1 }},
		{"fd_event", &Event_FdEvent{FdEvent: &FdEvent{Message: "open"}}, func(e *Event) bool { return e.GetFdEvent().GetMessage() == "open" }},
		{"locks", &Event_Locks{Locks: &LockSnapshot{Locks: []*LockEntry{{Uaddr: 10}}}}, func(e *Event) bool { return len(e.GetLocks().GetLocks()) == 1 }},
		{"timeline", &Event_Timeline{Timeline: &TimelineEvent{Message: "tick"}}, func(e *Event) bool { return e.GetTimeline().GetMessage() == "tick" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := proto.Marshal(&Event{Payload: tc.payload})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			got := &Event{}
			if err := proto.Unmarshal(wire, got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if !tc.check(got) {
				t.Errorf("payload %q did not survive round-trip: %v", tc.name, got)
			}
		})
	}
}
