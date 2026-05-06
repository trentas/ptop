//go:build linux && ebpf

package collector

import (
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/trentas/ptop/internal/bpf"
)

// NetworkEBPFCollector combines:
//   - tracepoint sock:inet_sock_set_state — discovers 5-tuple + state +
//     handshake RTT (SYN_SENT → ESTABLISHED).
//   - kprobes on tcp_sendmsg/tcp_cleanup_rbuf — Tx/Rx bytes per connection,
//     correlated via the auxiliary sock_to_key map (skaddr → 5-tuple)
//     populated by the tracepoint itself.
//
// Publishes []NetConn every 500ms. Pre-existing connections (opened before
// attach) don't appear — a tracepoint limitation, since it only fires on
// state transitions.
type NetworkEBPFCollector struct {
	tracer   *bpf.NetTracer
	pid      int
	resolver *SocketResolver
	ch       chan interface{}
	stop     chan struct{}
}

func NewNetworkEBPFCollector() *NetworkEBPFCollector {
	return &NetworkEBPFCollector{
		ch:       make(chan interface{}, 4),
		stop:     make(chan struct{}),
		resolver: NewSocketResolver(),
	}
}

func (c *NetworkEBPFCollector) Start(pid int) error {
	tracer, err := bpf.OpenNetTracer(pid)
	if err != nil {
		return fmt.Errorf("network eBPF: %w", err)
	}
	c.tracer = tracer
	c.pid = pid
	// Synchronous bootstrap: populates the map with TCP connections that
	// already exist in /proc/<pid>/net/tcp{,6} before the first snapshot.
	// Without this, processes with keep-alive look empty until some transition.
	c.bootstrapFromProc()
	go c.publishLoop()
	return nil
}

func (c *NetworkEBPFCollector) Stop() {
	close(c.stop)
	if c.tracer != nil {
		_ = c.tracer.Close()
		c.tracer = nil
	}
}

func (c *NetworkEBPFCollector) Subscribe() <-chan interface{} {
	return c.ch
}

func (c *NetworkEBPFCollector) publishLoop() {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	// Re-seed every 5s to catch long-lived connections that didn't go through
	// any state transition during ptop's lifetime.
	const reseedEvery = 10 // 10 × 500ms = 5s
	tick := 0
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			tick++
			if tick%reseedEvery == 0 {
				c.bootstrapFromProc()
			}
			conns := c.snapshot()
			select {
			case c.ch <- conns:
			default:
			}
		}
	}
}

// bootstrapFromProc enumerates /proc/<pid>/fd/, identifies the process's
// socket FDs, resolves their inodes via /proc/net/tcp{,6} (SocketResolver)
// and seeds the eBPF net_conn_map with BPF_NOEXIST — existing entries
// (coming from the tracepoint) are preserved with their real state/RTT/bytes.
//
// Pre-existing seeded connections have zeroed tx/rx and zero RTT — without
// skaddr we can't correlate them with the kprobes. That's the trade-off of
// this approach (the alternative would be iterating sock objects via vmlinux.h).
func (c *NetworkEBPFCollector) bootstrapFromProc() {
	if c.tracer == nil || c.pid <= 0 {
		return
	}
	fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", c.pid))
	if err != nil {
		return
	}
	// Collect inodes of the process's socket FDs.
	inodes := make(map[uint64]struct{}, 16)
	for _, e := range fds {
		link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", c.pid, e.Name()))
		if err != nil {
			continue
		}
		if inode, ok := extractSocketInode(link); ok && inode != 0 {
			inodes[inode] = struct{}{}
		}
	}
	if len(inodes) == 0 {
		return
	}
	// Resolve via SocketResolver. The resolver has a 2s cache, but we call it
	// once here — forces a refresh if stale.
	for inode := range inodes {
		info, ok := c.resolver.Resolve(inode)
		if !ok {
			continue
		}
		if info.Family != "TCP" {
			continue
		}
		if info.StateNum == 0 {
			continue
		}
		key := bpf.NetConnKey{
			DAddr:  info.DAddr,
			SAddr:  info.SAddr,
			DPort:  info.DPort,
			SPort:  info.SPort,
			Family: info.AF,
		}
		_ = c.tracer.SeedConnection(key, info.StateNum)
	}
}

// snapshot reads the map and converts each entry into a NetConn. Filters
// out CLOSE (7) — closed connections aren't relevant to the "Active
// Connections" view. Sorts by most recent activity first.
func (c *NetworkEBPFCollector) snapshot() []NetConn {
	if c.tracer == nil {
		return nil
	}
	snaps, err := c.tracer.Stats()
	if err != nil {
		return nil
	}
	out := make([]NetConn, 0, len(snaps))
	for _, s := range snaps {
		if s.State == tcpStateCLOSE {
			continue
		}
		latMs := float64(s.RTTNs) / 1e6
		out = append(out, NetConn{
			Type:      "TCP",
			Remote:    formatNetAddr(s.DAddr.String(), s.DPort, s.Family),
			State:     mapTCPState(s.State),
			Dir:       directionFromBytes(s.TxBytes, s.RxBytes),
			LatencyMs: latMs,
			TxBytes:   s.TxBytes,
			RxBytes:   s.RxBytes,
		})
	}
	// Stable order: most recent first to avoid jumping rows in the terminal.
	sort.SliceStable(out, func(i, j int) bool {
		return snaps[i].LastNs > snaps[j].LastNs
	})
	return out
}

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

// directionFromBytes infers the connection's predominant "direction" from
// tx vs rx volume. "→" outbound (tx >> rx), "←" inbound (rx >> tx),
// "↔" balanced or both zero. It's just a visual indicator — doesn't change
// what the user sees of the remote.
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
