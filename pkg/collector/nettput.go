package collector

import "time"

// netAccumulator turns per-connection byte counters into the target's monotonic
// totals (#128).
//
// It runs INSIDE the collector, against every connection the kernel map holds,
// because that is the only place the whole picture exists. By the time a
// snapshot is published the closed connections have been filtered out of it —
// rightly, they are not active — and their bytes went with them. Summing the
// published list therefore produced totals that SAWTOOTHED back to zero every
// time a transfer finished: measured on a loopback workload, 0 → 2.5MB → 0 →
// 3.3MB → 0. A typical HTTP connection lives under a second, so for anything
// speaking HTTP most of the volume was visible only in flight.
//
// Three properties of the data make this more than a subtraction:
//
//   - CONNECTIONS DISAPPEAR. So it sums per-connection INCREASES rather than
//     differencing a grand total, which cannot go backwards when one entry
//     leaves.
//
//   - A CONNECTION CAN BE OLDER THAN THE OBSERVER, arriving with a large
//     cumulative count on its first sighting — every connection bootstrapped
//     from /proc at startup is one. Counting that as traffic would invent
//     volume out of history.
//
//     But baselining EVERY first sighting is the opposite error, and a worse
//     one for the traffic people actually have. A connection that opens and
//     closes between two reads is seen exactly once, so it contributed nothing
//     at all: measured on 50,000 short connections each writing a byte, the
//     axis reported SEVEN bytes. That is every HTTP request.
//
//     So the two cases are told apart rather than lumped: Born says whether the
//     tracer first saw the connection after it attached. A connection born
//     under observation has no history to invent, so its counters are new bytes
//     in full; one that predates the observer is baselined as before.
//
//   - THERE IS NO CONNECTION ID. The kernel keys its map by the 4-tuple, so
//     that is the identity here too — and a key's counter going backwards means
//     the tuple was reused by a new connection, not that bytes were un-sent.
//
// It takes readings rather than []NetConn deliberately: NetConn carries no
// local port, so two connections to one peer would share a key, and the reset
// branch above would then count one of them twice when the other closed.
type netAccumulator struct {
	last map[string]netCounters
	at   time.Time

	txTotal, rxTotal uint64 // monotonic since the first observation
}

type netCounters struct {
	tx, rx uint64
	born   bool
}

// observe folds one reading of every connection — closed ones included — into
// the running totals and returns the sample to publish.
//
// The first call establishes the baseline and reports zero rates, which is the
// only honest answer: nothing has been observed for any length of time yet.
//
// now is passed rather than read so the arithmetic is testable and so a caller
// batching several readings gets the interval it actually means.
func (n *netAccumulator) observe(readings []netByteReading, now time.Time) NetThroughputSample {
	// Two readings can still share a key if the kernel recycled a tuple within
	// one interval; sum them rather than letting the last one seen replace the
	// others.
	cur := make(map[string]netCounters, len(readings))
	for _, r := range readings {
		e := cur[r.Key]
		e.tx += r.Tx
		e.rx += r.Rx
		e.born = e.born || r.Born
		cur[r.Key] = e
	}

	var dTx, dRx uint64
	if n.last != nil {
		for k, now := range cur {
			prev, seen := n.last[k]
			switch {
			case !seen && now.born:
				// Born under observation: nothing it carries predates us, so
				// all of it is new — including a connection that opened, moved
				// its bytes and closed inside one interval, which is every HTTP
				// request and is seen exactly once.
				dTx += now.tx
				dRx += now.rx
			case !seen:
				// Older than the observer: baseline only. Whatever it had
				// already moved happened before anyone was watching.
			default:
				if now.tx >= prev.tx {
					dTx += now.tx - prev.tx
				} else {
					dTx += now.tx // the tuple now names a different connection
				}
				if now.rx >= prev.rx {
					dRx += now.rx - prev.rx
				} else {
					dRx += now.rx
				}
			}
		}
	}

	elapsed := now.Sub(n.at).Seconds()
	first := n.last == nil
	n.last, n.at = cur, now

	// The totals only ever grow, which is the whole point: a closed
	// connection's last bytes are added once and stay added.
	n.txTotal += dTx
	n.rxTotal += dRx

	out := NetThroughputSample{TxBytes: n.txTotal, RxBytes: n.rxTotal, Timestamp: now}
	if first || elapsed <= 0 {
		return out
	}
	out.TxBytesPerS = float64(dTx) / elapsed
	out.RxBytesPerS = float64(dRx) / elapsed
	return out
}

// netByteReading is one connection's cumulative counters as the kernel map
// currently holds them, keyed by its 4-tuple — CLOSED CONNECTIONS INCLUDED,
// which is the whole reason this is fed from inside the collector.
type netByteReading struct {
	Key    string
	Tx, Rx uint64
	// Born is true when the tracer first saw this connection after attaching,
	// which is what makes its counters new traffic rather than history.
	Born bool
}

// netTupleKey identifies a connection by the 4-tuple the kernel keys its own
// map with, which is the only identity that survives a connection closing and
// a port being reused.
func netTupleKey(saddr string, sport uint16, daddr string, dport uint16) string {
	return saddr + ":" + itoa(int(sport)) + "\x00" + daddr + ":" + itoa(int(dport))
}

// itoa avoids pulling strconv in for two small integers on a hot path.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
