package collector

import (
	"fmt"

	"github.com/trentas/ptop/internal/bpf"
)

// The eBPF network lane's rows, turned into NetConn. Build-tag-free so that
// the rules below are unit-tested on any OS, like network_error.go.

// Kernel TCP states (linux/tcp.h) — also used in sockets.go for the
// /proc/net/tcp parser, but there the values come in as hex strings.
const (
	tcpStateESTABLISHED uint32 = 1
	tcpStateSYN_SENT    uint32 = 2
	tcpStateSYN_RECV    uint32 = 3
	tcpStateFIN_WAIT1   uint32 = 4
	tcpStateFIN_WAIT2   uint32 = 5
	tcpStateTIME_WAIT   uint32 = 6
	tcpStateCLOSE       uint32 = 7
	tcpStateCLOSE_WAIT  uint32 = 8
	tcpStateLAST_ACK    uint32 = 9
	tcpStateLISTEN      uint32 = 10
	tcpStateCLOSING     uint32 = 11
)

// netConnFromRow is the published form of one row of the kernel's connection
// map, or false for a row that is not a connection.
//
//   - CLOSE: the connection is gone. Its bytes are in the throughput totals
//     already, and the caller prunes the row (#128, #133).
//   - LISTEN: a listener has no peer. Its row's remote is 0.0.0.0:0, which a
//     consumer counted as one more peer (#195).
//
// Origin is the kernel's when the program saw the open. Otherwise it is
// "accepted" when the bootstrap found the connection on one of the target's
// listening endpoints (seenOnListener, see listensOn), and unknown when not.
func netConnFromRow(s bpf.NetSnapshot, preexisting, seenOnListener bool) (NetConn, bool) {
	if s.State == tcpStateCLOSE || s.State == tcpStateLISTEN {
		return NetConn{}, false
	}
	nc := NetConn{
		Type:        "TCP",
		Local:       formatNetAddr(s.SAddr.String(), s.SPort, s.Family),
		Remote:      formatNetAddr(s.DAddr.String(), s.DPort, s.Family),
		State:       mapTCPState(s.State),
		Dir:         directionFromBytes(s.TxBytes, s.RxBytes),
		TxBytes:     s.TxBytes,
		RxBytes:     s.RxBytes,
		Preexisting: preexisting,
	}
	switch {
	case s.Origin == bpf.NetOriginConnected:
		nc.Origin = ConnOriginConnected
	case s.Origin == bpf.NetOriginAccepted, seenOnListener:
		nc.Origin = ConnOriginAccepted
	}
	if s.RTTMeasured {
		nc.LatencyMs, nc.RTTMeasured = float64(s.RTTNs)/1e6, true
	}
	return nc, true
}

// netEndpoint is one end of a socket as the kernel's tables give it: the
// address family, the address in network order (4 bytes for IPv4) and the port
// in host order.
type netEndpoint struct {
	family uint16
	addr   [16]byte
	port   uint16
}

// listensOn says whether local, a connection's own endpoint, is one the target
// is listening on. That is the origin of a connection the program did not see
// opened, because it is older than the capture (#195).
//
// An accepted connection is a child of its listener: same family, same local
// port, and the address the SYN arrived at, which a wildcard listener covers.
// A connect()ed socket gets an endpoint of its own, and the kernel refuses to
// bind one to an address and port a listener holds, unless both sockets set
// SO_REUSEPORT. That is the rule's one blind spot. A listener closed since the
// accept leaves the connection unknown, which is a gap, not a wrong answer.
func listensOn(listeners []netEndpoint, local netEndpoint) bool {
	for _, l := range listeners {
		if l.family != local.family || l.port != local.port {
			continue
		}
		if l.addr == ([16]byte{}) || l.addr == local.addr {
			return true
		}
	}
	return false
}

func mapTCPState(s uint32) string {
	switch s {
	case tcpStateESTABLISHED:
		return "ESTABLISHED"
	case tcpStateSYN_SENT:
		return "SYN_SENT"
	case tcpStateSYN_RECV:
		return "SYN_RECV"
	case tcpStateFIN_WAIT1:
		return "FIN_WAIT1"
	case tcpStateFIN_WAIT2:
		return "FIN_WAIT2"
	case tcpStateTIME_WAIT:
		return "TIME_WAIT"
	case tcpStateCLOSE_WAIT:
		return "CLOSE_WAIT"
	case tcpStateLAST_ACK:
		return "LAST_ACK"
	case tcpStateLISTEN:
		return "LISTEN"
	case tcpStateCLOSING:
		return "CLOSING"
	default:
		return "?"
	}
}

// directionFromBytes is the TUI's arrow: which way most of the bytes went.
// "→" when more than four times as many were sent as received, "←" the
// reverse, "↔" otherwise and before any byte. It says nothing about who opened
// the connection (a client downloading reads "←"), and it changes as the ratio
// does; NetConn.Origin is that (#195).
func directionFromBytes(tx, rx uint64) string {
	switch {
	case tx == 0 && rx == 0:
		return "↔"
	case tx > 0 && rx == 0:
		return "→"
	case rx > 0 && tx == 0:
		return "←"
	case tx > rx*4:
		return "→"
	case rx > tx*4:
		return "←"
	default:
		return "↔"
	}
}

func formatNetAddr(ip string, port uint16, family uint16) string {
	if family == 10 { // AF_INET6
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}
