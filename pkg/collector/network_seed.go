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

const seedConsequence = "They appear only after a state transition, so fan_out and peers " +
	"undercount a process that talks over persistent connections."
