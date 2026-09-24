package collector

import (
	"testing"
	"time"
)

func conn(remote string, tx, rx uint64) NetConn {
	return NetConn{Type: "TCP", Remote: remote, TxBytes: tx, RxBytes: rx}
}

func TestNetThroughputFirstSnapshotIsABaseline(t *testing.T) {
	var n NetThroughput
	t0 := time.Now()
	// A connection that has already moved a megabyte before ptop attached.
	tx, rx := n.Observe([]NetConn{conn("a:1", 1<<20, 1<<20)}, t0)
	if tx != 0 || rx != 0 {
		t.Errorf("first snapshot reported %v/%v — it invented traffic out of history", tx, rx)
	}
	tx, rx = n.Observe([]NetConn{conn("a:1", 1<<20+1000, 1<<20+2000)}, t0.Add(time.Second))
	if tx != 1000 || rx != 2000 {
		t.Errorf("got %v/%v, want 1000/2000 bytes per second", tx, rx)
	}
}

// The defect this exists for: the snapshot drops closed connections, so a sum
// over all of them FALLS when a transfer finishes, and a rate differenced from
// that total goes negative exactly when the network was busiest.
func TestNetThroughputSurvivesAClosedConnection(t *testing.T) {
	var n NetThroughput
	t0 := time.Now()
	n.Observe([]NetConn{conn("a:1", 1000, 0), conn("b:2", 500_000, 0)}, t0)
	// b finished and left the snapshot; a moved 200 more bytes.
	tx, _ := n.Observe([]NetConn{conn("a:1", 1200, 0)}, t0.Add(time.Second))
	if tx < 0 {
		t.Fatalf("negative throughput: %v", tx)
	}
	if tx != 200 {
		t.Errorf("got %v B/s, want 200 — differencing the TOTAL would have said -499800", tx)
	}
}

// A key whose counter went backwards is a reused peer address, not negative
// traffic.
func TestNetThroughputTreatsABackwardsCounterAsAReset(t *testing.T) {
	var n NetThroughput
	t0 := time.Now()
	n.Observe([]NetConn{conn("a:1", 900_000, 0)}, t0)
	tx, _ := n.Observe([]NetConn{conn("a:1", 300, 0)}, t0.Add(time.Second))
	if tx != 300 {
		t.Errorf("got %v, want the new connection's 300 bytes", tx)
	}
}

// Several connections to one peer fold under one key, and their bytes must sum
// rather than the last one seen replacing the others.
func TestNetThroughputSumsConnectionsSharingAKey(t *testing.T) {
	var n NetThroughput
	t0 := time.Now()
	n.Observe([]NetConn{conn("a:1", 100, 0), conn("a:1", 200, 0)}, t0)
	tx, _ := n.Observe([]NetConn{conn("a:1", 150, 0), conn("a:1", 400, 0)}, t0.Add(time.Second))
	if tx != 250 {
		t.Errorf("got %v, want 250 (300 → 550); taking one connection alone would say 200", tx)
	}
}

func TestNetThroughputDividesByTheRealInterval(t *testing.T) {
	var n NetThroughput
	t0 := time.Now()
	n.Observe([]NetConn{conn("a:1", 0, 0)}, t0)
	tx, _ := n.Observe([]NetConn{conn("a:1", 1000, 0)}, t0.Add(4*time.Second))
	if tx != 250 {
		t.Errorf("got %v B/s over 4s, want 250", tx)
	}
	// A repeated timestamp must not divide by zero.
	tx2, _ := n.Observe([]NetConn{conn("a:1", 2000, 0)}, t0.Add(4*time.Second))
	if tx2 != 0 {
		t.Errorf("a zero interval should report 0, got %v", tx2)
	}
}

func TestNetThroughputEmptySnapshotIsQuietNotNegative(t *testing.T) {
	var n NetThroughput
	t0 := time.Now()
	n.Observe([]NetConn{conn("a:1", 5000, 5000)}, t0)
	tx, rx := n.Observe(nil, t0.Add(time.Second))
	if tx != 0 || rx != 0 {
		t.Errorf("every connection closing should read as 0, got %v/%v", tx, rx)
	}
}
