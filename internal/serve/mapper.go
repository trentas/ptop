package serve

import (
	"time"

	"github.com/trentas/ptop/pkg/collector"
	pb "github.com/trentas/ptop/pkg/streampb"
)

// toEvent converts a value published on a collector channel into a stream
// Event. It handles exactly the concrete types the collectors emit (the same
// set the TUI's waitFor* handlers demux). Unknown values return nil and are
// skipped by the hub.
//
// The envelope timestamp comes from the value's own Timestamp where it has one,
// else the current time. Field copies are mechanical: the proto messages mirror
// collector/types.go 1:1.
func toEvent(pid int, v interface{}) *pb.Event {
	ev := &pb.Event{Pid: int32(pid)}

	switch x := v.(type) {
	case collector.CpuSample:
		ev.TsUnixNano = tsNano(x.Timestamp)
		ev.Category = pb.Category_CATEGORY_CPU
		ev.Payload = &pb.Event_Cpu{Cpu: &pb.CpuSample{UsagePct: x.UsagePct}}

	case map[string]uint64: // syscall counts
		ev.TsUnixNano = nowNano()
		ev.Category = pb.Category_CATEGORY_SYSCALL
		stats := make([]*pb.SyscallStat, 0, len(x))
		for name, count := range x {
			stats = append(stats, &pb.SyscallStat{Name: name, Count: count})
		}
		ev.Payload = &pb.Event_Syscalls{Syscalls: &pb.SyscallSnapshot{Stats: stats}}

	case []collector.NetConn:
		ev.TsUnixNano = nowNano()
		ev.Category = pb.Category_CATEGORY_NETWORK
		conns := make([]*pb.NetConn, len(x))
		for i, c := range x {
			conns[i] = &pb.NetConn{
				Fd: int32(c.FD), Type: c.Type, Remote: c.Remote, State: c.State,
				Dir: c.Dir, LatencyMs: c.LatencyMs, TxBytes: c.TxBytes, RxBytes: c.RxBytes,
			}
		}
		ev.Payload = &pb.Event_Network{Network: &pb.NetworkSnapshot{Conns: conns}}

	case collector.MemStats:
		ev.TsUnixNano = nowNano()
		ev.Category = pb.Category_CATEGORY_MEMORY
		ev.Payload = &pb.Event_Memory{Memory: &pb.MemStats{
			RssBytes: x.RSSBytes, HeapBytes: x.HeapBytes,
			PageFaults: x.PageFaults, AllocsPerS: x.AllocsPerS,
		}}

	case collector.HeapStats:
		ev.TsUnixNano = tsNano(x.Timestamp)
		ev.Category = pb.Category_CATEGORY_MEMORY
		ev.Payload = &pb.Event_Heap{Heap: &pb.HeapSnapshot{
			LiveHeapBytes:      x.LiveHeapBytes,
			AllocRate:          x.AllocRate,
			SuspectedLeakBytes: x.SuspectedLeakBytes,
			TopCallSites:       heapCallSites(x.TopCallSites),
		}}

	case collector.HeapEvent:
		ev.TsUnixNano = nowNano()
		ev.Category = pb.Category_CATEGORY_MEMORY
		ev.Payload = &pb.Event_HeapEvent{HeapEvent: &pb.HeapEvent{
			Op: x.Op, Size: x.Size, Addr: x.Addr,
			LifetimeMs: x.LifetimeMs, CallSite: x.CallSite, Large: x.Large,
		}}

	case []collector.ThreadInfo:
		ev.TsUnixNano = nowNano()
		ev.Category = pb.Category_CATEGORY_THREAD
		threads := make([]*pb.ThreadInfo, len(x))
		for i, t := range x {
			threads[i] = &pb.ThreadInfo{
				Tid: int32(t.TID), Name: t.Name, State: t.State,
				CpuPct: t.CPUPct, Waiting: t.Waiting, CtxSwitches: t.CtxSwitches,
			}
		}
		ev.Payload = &pb.Event_Threads{Threads: &pb.ThreadSnapshot{Threads: threads}}

	case collector.IOWaitSample:
		ev.TsUnixNano = tsNano(x.Timestamp)
		ev.Category = pb.Category_CATEGORY_IO
		ev.Payload = &pb.Event_IoWait{IoWait: &pb.IoWaitSample{Pct: x.Pct}}

	case collector.IOThroughputSample:
		ev.TsUnixNano = tsNano(x.Timestamp)
		ev.Category = pb.Category_CATEGORY_IO
		ev.Payload = &pb.Event_IoThroughput{IoThroughput: &pb.IoThroughputSample{
			ReadBytesPerS: x.ReadBytesPerS, WriteBytesPerS: x.WriteBytesPerS,
			ReadOps: x.ReadOps, WriteOps: x.WriteOps,
		}}

	case collector.IOEBPFSnapshot:
		ev.TsUnixNano = nowNano()
		ev.Category = pb.Category_CATEGORY_IO
		ev.Payload = &pb.Event_Io{Io: &pb.IoSnapshot{
			TopFiles:       fileStats(x.TopFiles),
			LatencyBuckets: latencyBuckets(x.Buckets),
		}}

	case []collector.FDEntry:
		ev.TsUnixNano = nowNano()
		ev.Category = pb.Category_CATEGORY_FD
		fds := make([]*pb.FdEntry, len(x))
		for i, f := range x {
			fds[i] = &pb.FdEntry{
				Fd: int32(f.FD), Type: f.Type, Desc: f.Desc, Flags: f.Flags,
				Bytes: f.Bytes, AgeMs: f.AgeMs, Active: f.Active,
			}
		}
		ev.Payload = &pb.Event_Fds{Fds: &pb.FdSnapshot{Fds: fds}}

	case collector.FDEvent:
		ev.TsUnixNano = tsNano(x.Timestamp)
		ev.Category = pb.Category_CATEGORY_FD
		ev.Payload = &pb.Event_FdEvent{FdEvent: &pb.FdEvent{Message: x.Message}}

	case []collector.LockEntry:
		ev.TsUnixNano = nowNano()
		ev.Category = pb.Category_CATEGORY_LOCK
		locks := make([]*pb.LockEntry, len(x))
		for i, l := range x {
			locks[i] = &pb.LockEntry{
				Uaddr: l.UAddr, Waiters: l.Waiters, Wakers: l.Wakers,
				WaitDelta: l.WaitDelta, LatencyMs: l.LatencyMs,
				LastWaitTid: int32(l.LastWaitTID), LastWakeTid: int32(l.LastWakeTID),
			}
		}
		ev.Payload = &pb.Event_Locks{Locks: &pb.LockSnapshot{Locks: locks}}

	case collector.TimelineEvent:
		ev.TsUnixNano = tsNano(x.Timestamp)
		ev.Category = timelineCategory(x.Category)
		ev.Payload = &pb.Event_Timeline{Timeline: &pb.TimelineEvent{Message: x.Message}}

	default:
		return nil
	}

	return ev
}

func heapCallSites(in []collector.HeapCallSite) []*pb.HeapCallSite {
	out := make([]*pb.HeapCallSite, len(in))
	for i, s := range in {
		out[i] = &pb.HeapCallSite{
			CallSite: s.CallSite, AddrHex: s.AddrHex, LiveBytes: s.LiveBytes,
			AllocCount: s.AllocCount, AvgLifetimeMs: s.AvgLifetimeMs, Suspected: s.Suspected,
			Func: s.Func, File: s.File, Line: int32(s.Line), Module: s.Module, Offset: s.Offset,
		}
	}
	return out
}

func fileStats(in []collector.IOFileStats) []*pb.IoFileStats {
	out := make([]*pb.IoFileStats, len(in))
	for i, f := range in {
		out[i] = &pb.IoFileStats{
			Path: f.Path, Type: f.Type, Reads: f.Reads, Writes: f.Writes,
			Bytes: f.Bytes, LatencyMs: f.LatencyMs, Fsyncs: f.Fsyncs,
		}
	}
	return out
}

func latencyBuckets(in []collector.LatencyBucket) []*pb.LatencyBucket {
	out := make([]*pb.LatencyBucket, len(in))
	for i, b := range in {
		out[i] = &pb.LatencyBucket{Label: b.Label, Read: b.Read, Write: b.Write}
	}
	return out
}

// timelineCategory maps the collector's timeline category string (the F7
// taxonomy) onto the proto enum. TimelineEvents flow from several collectors
// (FD, futex) carrying their own category.
func timelineCategory(s string) pb.Category {
	switch s {
	case "syscall":
		return pb.Category_CATEGORY_SYSCALL
	case "net":
		return pb.Category_CATEGORY_NETWORK
	case "mem":
		return pb.Category_CATEGORY_MEMORY
	case "cpu":
		return pb.Category_CATEGORY_CPU
	case "lock":
		return pb.Category_CATEGORY_LOCK
	case "io":
		return pb.Category_CATEGORY_IO
	case "fd":
		return pb.Category_CATEGORY_FD
	default:
		return pb.Category_CATEGORY_TIMELINE
	}
}

func tsNano(t time.Time) int64 {
	if t.IsZero() {
		return nowNano()
	}
	return t.UnixNano()
}

func nowNano() int64 { return time.Now().UnixNano() }
