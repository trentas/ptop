//go:build darwin

package collector

import (
	"fmt"
	"sort"
	"time"
)

// NetworkEBPFCollector — name preserved so model.go's wiring is OS-agnostic.
// On darwin there is no eBPF; this implementation enumerates open sockets
// every second via proc_pidinfo(PROC_PIDLISTFDS) + proc_pidfdinfo
// (PROC_PIDFDSOCKETINFO).
//
// Field semantics on darwin (differ from the Linux eBPF collector):
//   - LatencyMs (RTT): no public path. NEFilterDataProvider doesn't expose
//     it and PKTAP-based inference needs a system extension. Stays 0.
//   - TxBytes / RxBytes: macOS libproc has NO cumulative per-socket byte
//     counter. The only real signal is the current socket-buffer occupancy
//     (socket_info.soi_snd/soi_rcv.sbi_cc), so TxBytes/RxBytes here are the
//     bytes currently QUEUED in the send/receive buffers, not lifetime
//     totals. A non-zero value means the kernel is holding data the peer
//     (Tx) or the process (Rx) hasn't drained yet — useful as a backlog
//     indicator, but the F3 "Traffic" column must be read as a gauge, not
//     a counter. See LPSocketFDInfo.SndQueued/RcvQueued.
//   - Dir (→/←/↔): inferred from local vs remote address presence.
//
// The label "eBPF" in the type name lies on darwin; the source string is
// fixed up in the model layer (see task #5 / issue #22).

type NetworkEBPFCollector struct {
	pid  int
	ch   chan interface{}
	stop chan struct{}
}

func NewNetworkEBPFCollector() *NetworkEBPFCollector {
	return &NetworkEBPFCollector{
		ch:   make(chan interface{}, 16),
		stop: make(chan struct{}),
	}
}

func (c *NetworkEBPFCollector) Start(pid int) error {
	c.pid = pid
	if _, err := ListFDs(pid); err != nil {
		return fmt.Errorf("Network collector unavailable for pid %d: %w", pid, err)
	}
	go c.loop()
	return nil
}

func (c *NetworkEBPFCollector) Stop()                          { close(c.stop) }
func (c *NetworkEBPFCollector) Subscribe() <-chan interface{}  { return c.ch }

func (c *NetworkEBPFCollector) loop() {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	c.collectAndEmit()
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			c.collectAndEmit()
		}
	}
}

func (c *NetworkEBPFCollector) collectAndEmit() {
	conns, err := c.collect()
	if err != nil {
		return
	}
	select {
	case c.ch <- conns:
	default:
	}
}

func (c *NetworkEBPFCollector) collect() ([]NetConn, error) {
	fds, err := ListFDs(c.pid)
	if err != nil {
		return nil, err
	}
	out := make([]NetConn, 0, len(fds))
	for _, raw := range fds {
		if raw.Type != FDTypeSocket {
			continue
		}
		s, err := FDSocketInfo(c.pid, raw.FD)
		if err != nil {
			continue
		}
		nc := socketToNetConn(int(raw.FD), s)
		// Skip degenerate entries (no protocol info we can label).
		if nc.Type == "" {
			continue
		}
		out = append(out, nc)
	}

	// A macOS process typically holds many idle UDP sockets bound to the
	// wildcard address plus a few real connections. proc_pidinfo lists them
	// in FD order, which buries the interesting ESTABLISHED connections at
	// the bottom where the F3 panel's row limit clips them. Sort so the most
	// useful rows surface first: connected (has a remote peer) before
	// listeners/idle, TCP before UDP, then by remote for stable ordering.
	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := connRank(out[i]), connRank(out[j]); ri != rj {
			return ri < rj
		}
		if out[i].Type != out[j].Type {
			return typeRank(out[i].Type) < typeRank(out[j].Type)
		}
		return out[i].Remote < out[j].Remote
	})
	return out, nil
}

// connRank orders connections by usefulness: an active peer connection first,
// then anything with a TCP state (e.g. a listener), then idle/unconnected.
func connRank(c NetConn) int {
	switch {
	case c.Dir == "↔": // has a remote peer
		return 0
	case c.State != "": // TCP socket with a state but no peer (listener, etc.)
		return 1
	default: // unconnected UDP / wildcard
		return 2
	}
}

func typeRank(t string) int {
	switch t {
	case "TCP":
		return 0
	case "UDP":
		return 1
	default:
		return 2
	}
}

// socketToNetConn maps the libproc LPSocketFDInfo into the public NetConn
// type used by the F3 view. Direction is inferred: a connection with a
// remote address is bidirectional ("↔"); a listener has no remote ("←").
func socketToNetConn(fd int, s LPSocketFDInfo) NetConn {
	var protoLabel, state, dir string

	switch s.Family {
	case 2: // AF_INET
		if s.SockType == 1 {
			protoLabel = "TCP"
			state = tcpStateLabel(s.TCPState)
		} else {
			protoLabel = "UDP"
		}
	case 30: // AF_INET6
		if s.SockType == 1 {
			protoLabel = "TCP"
			state = tcpStateLabel(s.TCPState)
		} else {
			protoLabel = "UDP"
		}
	case 1: // AF_UNIX
		protoLabel = "UNIX"
	default:
		// Skip — types.NetConn.Type only knows TCP/UDP/UNIX.
	}

	remote := s.RemoteAddr
	if remote == "0.0.0.0:0" || remote == "[::]:0" {
		remote = ""
	}
	if remote == "" {
		dir = "←" // listening / passive
	} else {
		dir = "↔"
	}

	return NetConn{
		FD:        fd,
		Type:      protoLabel,
		Remote:    pickRemoteOrLocal(s.LocalAddr, remote),
		State:     state,
		Dir:       dir,
		LatencyMs: 0,
		// Queued buffer occupancy, not cumulative traffic — see file header.
		TxBytes: s.SndQueued,
		RxBytes: s.RcvQueued,
	}
}

// pickRemoteOrLocal returns the remote endpoint when present (it's the more
// useful label for the connection list); otherwise falls back to the local
// bind, so listeners still get a meaningful row.
func pickRemoteOrLocal(local, remote string) string {
	if remote != "" {
		return remote
	}
	return local
}

func tcpStateLabel(s int32) string {
	switch s {
	case TCPStateClosed:
		return "CLOSED"
	case TCPStateListen:
		return "LISTEN"
	case TCPStateSynSent:
		return "SYN_SENT"
	case TCPStateSynReceived:
		return "SYN_RECV"
	case TCPStateEstablished:
		return "ESTABLISHED"
	case TCPStateCloseWait:
		return "CLOSE_WAIT"
	case TCPStateFinWait1:
		return "FIN_WAIT1"
	case TCPStateClosing:
		return "CLOSING"
	case TCPStateLastAck:
		return "LAST_ACK"
	case TCPStateFinWait2:
		return "FIN_WAIT2"
	case TCPStateTimeWait:
		return "TIME_WAIT"
	default:
		return ""
	}
}
