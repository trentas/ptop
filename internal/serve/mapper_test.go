package serve

import (
	"testing"
	"time"

	"github.com/trentas/ptop/pkg/collector"
	pb "github.com/trentas/ptop/pkg/streampb"
)

func TestToEventCategoriesAndPayloads(t *testing.T) {
	const pid = 1234
	cases := []struct {
		name string
		in   interface{}
		cat  pb.Category
		ok   func(*pb.Event) bool
	}{
		{"cpu", collector.CpuSample{UsagePct: 42, Timestamp: time.Unix(1, 0)},
			pb.Category_CATEGORY_CPU, func(e *pb.Event) bool { return e.GetCpu().GetUsagePct() == 42 }},
		{"syscalls", map[string]uint64{"read": 3, "write": 5},
			pb.Category_CATEGORY_SYSCALL, func(e *pb.Event) bool { return len(e.GetSyscalls().GetStats()) == 2 }},
		{"network", []collector.NetConn{{FD: 7, Type: "TCP", Remote: "1.2.3.4:80"}},
			pb.Category_CATEGORY_NETWORK, func(e *pb.Event) bool {
				c := e.GetNetwork().GetConns()
				return len(c) == 1 && c[0].GetFd() == 7 && c[0].GetType() == "TCP"
			}},
		{"memory", collector.MemStats{RSSBytes: 1000, AllocsPerS: 9},
			pb.Category_CATEGORY_MEMORY, func(e *pb.Event) bool { return e.GetMemory().GetRssBytes() == 1000 }},
		{"threads", []collector.ThreadInfo{{TID: 11, Name: "main", CtxSwitches: 4}},
			pb.Category_CATEGORY_THREAD, func(e *pb.Event) bool {
				th := e.GetThreads().GetThreads()
				return len(th) == 1 && th[0].GetTid() == 11 && th[0].GetCtxSwitches() == 4
			}},
		{"io_wait", collector.IOWaitSample{Pct: 12.5, Timestamp: time.Unix(2, 0)},
			pb.Category_CATEGORY_IO, func(e *pb.Event) bool { return e.GetIoWait().GetPct() == 12.5 }},
		{"io_throughput", collector.IOThroughputSample{ReadBytesPerS: 100, WriteOps: 3, Timestamp: time.Unix(3, 0)},
			pb.Category_CATEGORY_IO, func(e *pb.Event) bool { return e.GetIoThroughput().GetReadBytesPerS() == 100 }},
		{"io_snapshot", collector.IOEBPFSnapshot{
			TopFiles: []collector.IOFileStats{{Path: "/x", Reads: 2}},
			Buckets:  []collector.LatencyBucket{{Label: "1ms", Read: 1}},
		}, pb.Category_CATEGORY_IO, func(e *pb.Event) bool {
			io := e.GetIo()
			return len(io.GetTopFiles()) == 1 && io.GetTopFiles()[0].GetPath() == "/x" && len(io.GetLatencyBuckets()) == 1
		}},
		{"fds", []collector.FDEntry{{FD: 5, Type: "socket", Active: true}},
			pb.Category_CATEGORY_FD, func(e *pb.Event) bool {
				f := e.GetFds().GetFds()
				return len(f) == 1 && f[0].GetFd() == 5 && f[0].GetActive()
			}},
		{"fd_event", collector.FDEvent{Message: "openat /etc/hosts", Timestamp: time.Unix(4, 0)},
			pb.Category_CATEGORY_FD, func(e *pb.Event) bool { return e.GetFdEvent().GetMessage() == "openat /etc/hosts" }},
		{"locks", []collector.LockEntry{{UAddr: 0xdead, Waiters: 2, LastWaitTID: 9}},
			pb.Category_CATEGORY_LOCK, func(e *pb.Event) bool {
				l := e.GetLocks().GetLocks()
				return len(l) == 1 && l[0].GetUaddr() == 0xdead && l[0].GetLastWaitTid() == 9
			}},
		{"timeline_lock", collector.TimelineEvent{Category: "lock", Message: "futex", Timestamp: time.Unix(5, 0)},
			pb.Category_CATEGORY_LOCK, func(e *pb.Event) bool { return e.GetTimeline().GetMessage() == "futex" }},
		{"timeline_net", collector.TimelineEvent{Category: "net", Message: "connect"},
			pb.Category_CATEGORY_NETWORK, func(e *pb.Event) bool { return e.GetTimeline().GetMessage() == "connect" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := toEvent(pid, tc.in)
			if ev == nil {
				t.Fatalf("toEvent returned nil for %T", tc.in)
			}
			if ev.GetPid() != pid {
				t.Errorf("pid = %d, want %d", ev.GetPid(), pid)
			}
			if ev.GetCategory() != tc.cat {
				t.Errorf("category = %v, want %v", ev.GetCategory(), tc.cat)
			}
			if ev.GetTsUnixNano() == 0 {
				t.Errorf("ts_unix_nano not set")
			}
			if !tc.ok(ev) {
				t.Errorf("payload check failed: %v", ev)
			}
		})
	}
}

func TestToEventUnknownReturnsNil(t *testing.T) {
	if ev := toEvent(1, "not a collector value"); ev != nil {
		t.Errorf("expected nil for unknown type, got %v", ev)
	}
	if ev := toEvent(1, 42); ev != nil {
		t.Errorf("expected nil for unknown type, got %v", ev)
	}
}

// A value carrying a timestamp uses it; one without falls back to now.
func TestToEventTimestamp(t *testing.T) {
	ts := time.Unix(100, 500)
	ev := toEvent(1, collector.CpuSample{UsagePct: 1, Timestamp: ts})
	if ev.GetTsUnixNano() != ts.UnixNano() {
		t.Errorf("ts = %d, want %d", ev.GetTsUnixNano(), ts.UnixNano())
	}

	before := time.Now().UnixNano()
	ev = toEvent(1, collector.MemStats{RSSBytes: 1})
	if ev.GetTsUnixNano() < before {
		t.Errorf("ts = %d, expected >= %d (now)", ev.GetTsUnixNano(), before)
	}
}
