package collector

import "time"

// Network throughput, derived from the per-connection byte counters a NetConn
// snapshot already carries.
//
// ─── Why this is a helper and not another wire payload ──────────────────────
//
// The bytes are already on the stream: every NetConn carries cumulative TxBytes
// and RxBytes. Publishing a second payload that restates them as a rate would
// put the same measurement on the wire twice, and the two would disagree the
// first time one of them changed.
//
// But the derivation is not the subtraction it looks like, and leaving every
// consumer to discover that for itself is how two implementations drift into
// two different answers. Three things make it awkward, all of them properties
// of the snapshot rather than of the network:
//
//   - CLOSED CONNECTIONS LEAVE. The snapshot drops a connection once it closes
//     (see NetworkEBPFCollector.snapshot), so the naive sum over all
//     connections FALLS, and a rate taken from it goes negative exactly when a
//     busy transfer finishes. Summing per-connection increases instead of
//     differencing the total is what avoids that.
//   - A CONNECTION IS OLDER THAN THE OBSERVER. One that existed before ptop
//     attached arrives with a large cumulative count on its first snapshot.
//     Counting that as traffic in the current window invents a spike out of
//     history, so a connection's first sighting sets a baseline and contributes
//     nothing — the same discipline the CPU collector uses at Start.
//   - THERE IS NO CONNECTION ID. The eBPF lane leaves FD at zero, so the only
//     identity available is the peer address, and two simultaneous connections
//     to one peer fold together. For a throughput total that is harmless — they
//     are summed either way — but it does mean a key's counter can go backwards
//     when one of the two closes, which is handled as a reset rather than as
//     negative traffic.
//
// It is deliberately not a Collector: it has no lifecycle, no channel and
// nothing to attach. Feed it snapshots, get rates.
type NetThroughput struct {
	last map[string]netCounters
	at   time.Time
}

type netCounters struct {
	tx, rx uint64
}

// Observe takes a snapshot and returns bytes per second since the previous
// call. The first call establishes the baseline and returns zeroes, which is
// the only honest answer: nothing has been observed for any length of time yet.
//
// now is passed rather than read so the arithmetic is testable and so a caller
// batching several snapshots gets the interval it actually means.
func (n *NetThroughput) Observe(conns []NetConn, now time.Time) (txPerSec, rxPerSec float64) {
	// One snapshot can hold several connections under one key; sum them before
	// differencing, or the last one seen would silently replace the others.
	cur := make(map[string]netCounters, len(conns))
	for _, c := range conns {
		k := netKey(c)
		e := cur[k]
		e.tx += c.TxBytes
		e.rx += c.RxBytes
		cur[k] = e
	}

	var dTx, dRx uint64
	if n.last != nil {
		for k, now := range cur {
			prev, seen := n.last[k]
			switch {
			case !seen:
				// First sighting: baseline only. Whatever it had already
				// transferred happened before anyone was watching.
			case now.tx >= prev.tx:
				dTx += now.tx - prev.tx
			default:
				dTx += now.tx // counter reset, or the key now names another connection
			}
			switch {
			case !seen:
			case now.rx >= prev.rx:
				dRx += now.rx - prev.rx
			default:
				dRx += now.rx
			}
		}
	}

	elapsed := now.Sub(n.at).Seconds()
	first := n.last == nil
	n.last, n.at = cur, now
	if first || elapsed <= 0 {
		return 0, 0
	}
	return float64(dTx) / elapsed, float64(dRx) / elapsed
}

// netKey identifies a connection across snapshots.
//
// Peer address and transport, not FD: the eBPF lane never sets FD, so keying on
// it would put every connection in one bucket. See the type comment for what
// that costs.
func netKey(c NetConn) string { return c.Type + "\x00" + c.Remote }
