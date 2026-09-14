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

// The defect #121 is about: a collector writes both classes to ONE channel, and
// a per-occurrence flood used to take every slot, so the collector's own
// timer-driven snapshot was thrown away at the first hop — before the bus
// reserve upstream ever got a chance to protect it.
func TestPublishFloodDoesNotStarveTheSnapshot(t *testing.T) {
	ch := make(chan interface{}, 64)

	// Far more events than the queue holds, exactly as a 700k/s allocator does.
	var accepted int
	for i := 0; i < 10_000; i++ {
		if publish(ch, HeapEvent{Size: 128}) {
			accepted++
		}
	}
	if want := perOccurrenceLimitOf(64); accepted != want {
		t.Errorf("flood took %d slots, want it capped at %d", accepted, want)
	}

	// The whole point: the snapshot still fits behind the flood.
	if !publish(ch, HeapStats{AllocRate: 689648, TotalCallSites: 1}) {
		t.Fatal("snapshot shed behind a per-occurrence flood — this is #121")
	}

	// And it is the snapshot that comes out, not a lost one.
	var gotStats bool
	for len(ch) > 0 {
		if _, ok := (<-ch).(HeapStats); ok {
			gotStats = true
		}
	}
	if !gotStats {
		t.Error("no HeapStats in the queue after publishing one")
	}
}

// A snapshot may use the whole queue — the reserve holds back the flood, not
// the thing being protected. Once genuinely full, publish reports the drop
// rather than blocking a collector's publish loop.
func TestPublishSnapshotsMayFillTheQueue(t *testing.T) {
	ch := make(chan interface{}, 4)
	for i := 0; i < 4; i++ {
		if !publish(ch, CpuSample{UsagePct: 1}) {
			t.Fatalf("snapshot %d shed with room left", i)
		}
	}
	if publish(ch, CpuSample{UsagePct: 1}) {
		t.Error("publish accepted a value into a full queue")
	}
	if publish(ch, HeapEvent{}) {
		t.Error("publish accepted an event into a full queue")
	}
}

// A queue carrying only snapshots is unaffected by the reserve, so collectors
// that never emit per-occurrence values behave exactly as before.
func TestPublishLeavesSnapshotOnlyCollectorsAlone(t *testing.T) {
	ch := make(chan interface{}, 8)
	for i := 0; i < 8; i++ {
		if !publish(ch, MemStats{}) {
			t.Fatalf("snapshot %d shed with room left", i)
		}
	}
}
