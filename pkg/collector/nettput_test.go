package collector

import (
	"testing"
	"time"
)

func rd(key string, tx, rx uint64) netByteReading {
	return netByteReading{Key: key, Tx: tx, Rx: rx}
}

func TestNetTotalsFirstReadingIsABaseline(t *testing.T) {
	var n netAccumulator
	t0 := time.Now()
	// A connection that already moved a megabyte before ptop attached — every
	// connection bootstrapped from /proc looks like this.
	s := n.observe([]netByteReading{rd("a", 1<<20, 1<<20)}, t0)
	if s.TxBytes != 0 || s.RxBytes != 0 || s.TxBytesPerS != 0 {
		t.Errorf("first reading reported %+v — it invented volume out of history", s)
	}
	s = n.observe([]netByteReading{rd("a", 1<<20+1000, 1<<20+2000)}, t0.Add(time.Second))
	if s.TxBytes != 1000 || s.RxBytes != 2000 {
		t.Errorf("totals = %d/%d, want 1000/2000", s.TxBytes, s.RxBytes)
	}
	if s.TxBytesPerS != 1000 || s.RxBytesPerS != 2000 {
		t.Errorf("rates = %v/%v, want 1000/2000 per second", s.TxBytesPerS, s.RxBytesPerS)
	}
}

// The defect this exists for, stated as a test: a connection that finishes and
// leaves must not take its bytes with it. The published list sawtoothed to zero
// every time a transfer completed — 0 → 2.5MB → 0 — which reads as traffic
// stopping rather than as a connection closing.
func TestNetTotalsSurviveAConnectionLeaving(t *testing.T) {
	var n netAccumulator
	t0 := time.Now()
	n.observe([]netByteReading{rd("keep", 0, 0), rd("transfer", 0, 0)}, t0)
	s := n.observe([]netByteReading{rd("keep", 100, 0), rd("transfer", 2_500_000, 0)}, t0.Add(time.Second))
	if s.TxBytes != 2_500_100 {
		t.Fatalf("totals = %d, want 2500100", s.TxBytes)
	}
	// "transfer" closed and was recycled out of the map.
	s = n.observe([]netByteReading{rd("keep", 200, 0)}, t0.Add(2*time.Second))
	if s.TxBytes != 2_500_200 {
		t.Errorf("totals = %d after a connection left, want 2500200 — they must not go back", s.TxBytes)
	}
	if s.TxBytesPerS != 100 {
		t.Errorf("rate = %v, want 100; differencing the grand total would report -2499900", s.TxBytesPerS)
	}
}

// Monotonic is the contract. Nothing a connection does may make the totals fall.
func TestNetTotalsNeverDecrease(t *testing.T) {
	var n netAccumulator
	t0 := time.Now()
	prev := uint64(0)
	readings := [][]netByteReading{
		{rd("a", 0, 0)},
		{rd("a", 5000, 0), rd("b", 9000, 0)},
		{rd("a", 5000, 0)}, // b left
		{},                 // everything left
		{rd("c", 700, 0)},  // a fresh tuple
		{rd("c", 10, 0)},   // the tuple was reused by a new connection
	}
	for i, r := range readings {
		s := n.observe(r, t0.Add(time.Duration(i)*time.Second))
		if s.TxBytes < prev {
			t.Fatalf("step %d: totals fell from %d to %d", i, prev, s.TxBytes)
		}
		if s.TxBytesPerS < 0 {
			t.Fatalf("step %d: negative rate %v", i, s.TxBytesPerS)
		}
		prev = s.TxBytes
	}
}

func TestNetTotalsDivideByTheRealInterval(t *testing.T) {
	var n netAccumulator
	t0 := time.Now()
	n.observe([]netByteReading{rd("a", 0, 0)}, t0)
	s := n.observe([]netByteReading{rd("a", 1000, 0)}, t0.Add(4*time.Second))
	if s.TxBytesPerS != 250 {
		t.Errorf("rate = %v over 4s, want 250", s.TxBytesPerS)
	}
	// A repeated timestamp must not divide by zero, and must not lose the bytes.
	s = n.observe([]netByteReading{rd("a", 3000, 0)}, t0.Add(4*time.Second))
	if s.TxBytesPerS != 0 {
		t.Errorf("a zero interval has no rate, got %v", s.TxBytesPerS)
	}
	if s.TxBytes != 3000 {
		t.Errorf("the bytes must still be counted, got %d", s.TxBytes)
	}
}

// The 4-tuple is the key because NetConn's peer address alone is not unique:
// two connections to one peer differ only in the local port.
func TestNetTupleKeySeparatesLocalPorts(t *testing.T) {
	a := netTupleKey("10.0.0.1", 5000, "10.0.0.2", 443)
	b := netTupleKey("10.0.0.1", 5001, "10.0.0.2", 443)
	if a == b {
		t.Error("two connections to one peer from different local ports are not one connection")
	}
	if a != netTupleKey("10.0.0.1", 5000, "10.0.0.2", 443) {
		t.Error("the key must be stable")
	}
}

// Baselining every first sighting is right for a connection that predates the
// observer and catastrophic for one that does not. A connection that opens,
// transfers and closes inside one interval is seen exactly ONCE, so it used to
// contribute nothing at all — measured on 50,000 short connections each writing
// a byte, the axis reported seven.
func TestNetTotalsCountAConnectionBornUnderObservation(t *testing.T) {
	var n netAccumulator
	t0 := time.Now()
	n.observe(nil, t0) // attach: nothing in flight

	// One connection lived and died entirely inside this interval.
	s := n.observe([]netByteReading{{Key: "short", Tx: 900, Rx: 100, Born: true}}, t0.Add(time.Second))
	if s.TxBytes != 900 || s.RxBytes != 100 {
		t.Errorf("totals = %d/%d, want 900/100 — a connection seen once still moved bytes", s.TxBytes, s.RxBytes)
	}

	// And it must not be counted again when it lingers a tick before pruning.
	s = n.observe([]netByteReading{{Key: "short", Tx: 900, Rx: 100, Born: true}}, t0.Add(2*time.Second))
	if s.TxBytes != 900 {
		t.Errorf("totals = %d after re-reading the same counters, want 900", s.TxBytes)
	}
}

// The other half of the rule: a connection already running when ptop attached
// carries history, and counting it would invent volume out of the past.
func TestNetTotalsStillBaselineAPreExistingConnection(t *testing.T) {
	var n netAccumulator
	t0 := time.Now()
	n.observe(nil, t0)
	s := n.observe([]netByteReading{{Key: "old", Tx: 1 << 20, Rx: 1 << 20, Born: false}}, t0.Add(time.Second))
	if s.TxBytes != 0 {
		t.Errorf("totals = %d, want 0 — that megabyte moved before anyone was watching", s.TxBytes)
	}
	s = n.observe([]netByteReading{{Key: "old", Tx: 1<<20 + 500, Rx: 1 << 20, Born: false}}, t0.Add(2*time.Second))
	if s.TxBytes != 500 {
		t.Errorf("totals = %d, want the 500 bytes it moved under observation", s.TxBytes)
	}
}
