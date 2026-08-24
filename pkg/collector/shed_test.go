package collector

import "testing"

func TestIsPerOccurrenceValue(t *testing.T) {
	perOccurrence := []interface{}{
		HeapEvent{Op: "alloc"},
		FDEvent{},
		TimelineEvent{},
		NetError{},
		FSEvent{},
		SignalEvent{},
		TLSPayload{},
		ProcLifecycleEvent{},
		SecurityEvent{},
	}
	for _, v := range perOccurrence {
		if !isPerOccurrenceValue(v) {
			t.Errorf("%T: isPerOccurrenceValue = false, want true", v)
		}
	}

	snapshots := []interface{}{
		CpuSample{},
		MemStats{},
		HeapStats{},
		[]ThreadInfo{},
		[]LockEntry{},
		[]NetConn{},
		[]FDEntry{},
		IOWaitSample{},
		IOThroughputSample{},
		ProcContext{},
		map[string]uint64{},
	}
	for _, v := range snapshots {
		if isPerOccurrenceValue(v) {
			t.Errorf("%T: isPerOccurrenceValue = true, want false", v)
		}
	}
}

func TestPerOccurrenceLimitOf(t *testing.T) {
	cases := []struct{ buffer, want int }{
		{256, 192}, {64, 48}, {4, 3}, {2, 1}, {1, 1},
	}
	for _, tc := range cases {
		if got := perOccurrenceLimitOf(tc.buffer); got != tc.want {
			t.Errorf("perOccurrenceLimitOf(%d) = %d, want %d", tc.buffer, got, tc.want)
		}
	}
}

// A subscription that has stopped reading still has to receive the periodic
// snapshots while a per-occurrence axis floods (#108).
func TestSubscriptionFloodDoesNotStarveSnapshots(t *testing.T) {
	b := NewBus()
	sub := b.Subscribe(64)
	defer sub.Close()

	for i := 0; i < 500; i++ {
		b.broadcast(HeapEvent{Op: "alloc", Size: 64})
	}
	b.broadcast(CpuSample{UsagePct: 42})

	var cpu, alloc int
	for len(sub.C()) > 0 {
		switch (<-sub.C()).(type) {
		case CpuSample:
			cpu++
		case HeapEvent:
			alloc++
		}
	}
	if cpu != 1 {
		t.Errorf("CpuSample delivered = %d, want 1", cpu)
	}
	if alloc != perOccurrenceLimitOf(64) {
		t.Errorf("HeapEvents queued = %d, want the limit %d", alloc, perOccurrenceLimitOf(64))
	}
	if sub.Dropped() == 0 {
		t.Error("shed values were not counted")
	}
}
