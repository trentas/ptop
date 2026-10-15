//go:build linux

package collector

import "fmt"

// seedReport is what one bootstrap of pre-existing connections managed (#140).
//
// The tracepoint the network probe hangs on fires on state transitions, so a
// connection opened before the attach is invisible until something moves it.
// The bootstrap closes that gap by reading the target's fds and seeding the map.
// When it cannot, the probe is still ACTIVE — new connections are tracked — but
// a client living on keep-alive connections publishes fan_out 0, and a consumer
// reads that as "talks to nobody". The report is what lets the probe say so.
type seedReport struct {
	fdErr    error // reading /proc/<pid>/fd failed
	sockets  int   // socket inodes among the target's fds
	resolved int   // of those, found in the target's socket tables
}

// caveat is the qualifier the network probe carries for this report, or "" when
// the bootstrap saw what it was meant to see.
//
// Only a bootstrap that resolved NOTHING is reported. Some unresolved inodes are
// routine — netlink and packet sockets are fds too, and they have no table here
// — so a partial count would cry wolf on every Go process.
func (r seedReport) caveat(pid int) string {
	switch {
	case r.fdErr != nil:
		return fmt.Sprintf("connections opened before the capture were not seeded: "+
			"reading /proc/%d/fd failed (%v). %s", pid, r.fdErr, seedConsequence)
	case r.sockets > 0 && r.resolved == 0:
		return fmt.Sprintf("connections opened before the capture were not seeded: "+
			"none of the target's %d socket(s) is in /proc/%d/net. %s", r.sockets, pid, seedConsequence)
	}
	return ""
}

// cgroupSeedCaveat is the same gap in cgroup scope, where it is structural: the
// bootstrap needs a pid, and a subtree has none (#94).
const cgroupSeedCaveat = "cgroup scope: connections opened before the capture are not seeded (that needs a pid). " +
	seedConsequence

const seedConsequence = "They appear only once they move a byte or change state, so fan_out and peers " +
	"undercount a process that talks over persistent connections."

// kprobeLaneCaveat qualifies the byte lane kernels before 6.4 get. It counts
// received bytes at a kprobe on tcp_cleanup_rbuf, and measured on one kernel
// build the call that carries the byte count was inlined into tcp_recvmsg: the
// kprobe fired, never with a byte, and every connection read rx 0 — which is
// indistinguishable from a connection that received nothing.
const kprobeLaneCaveat = "this kernel predates the sock_recv_length tracepoint (6.4), so received bytes are " +
	"counted at a kprobe on tcp_cleanup_rbuf; a kernel build that inlines that call reports rx 0 for every " +
	"connection — ebpf-selftest checks this host"

// joinCaveats joins two qualifiers on one probe, either of which may be empty.
func joinCaveats(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + "; " + b
}
