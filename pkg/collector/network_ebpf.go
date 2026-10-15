//go:build linux && ebpf

package collector

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/trentas/ptop/internal/bpf"
)

// NetworkEBPFCollector combines:
//
//   - tracepoint sock:inet_sock_set_state — every state transition: the
//     connection's lifecycle and its handshake RTT (SYN_SENT → ESTABLISHED).
//
//   - one byte lane — the sock_{send,recv}_length tracepoints where the kernel
//     has them, kprobes on tcp_sendmsg/tcp_cleanup_rbuf otherwise.
//
//   - kprobes on tcp_reset/tcp_retransmit_skb — network errors (#56), delivered
//     per-event via a ring buffer.
//
// Which sockets are the target's is decided in the kernel, by evidence rather
// than by whichever task a softirq interrupted (#135): the target connected
// it, moved bytes on it, closed it, or it matches a row seeded from the
// target's own fds. network.bpf.c has the whole argument and the measurements.
//
// Publishes []NetConn every 500ms, plus a NetError per error event. Connections
// opened before the attach are seeded from /proc (bootstrapFromProc) and adopted
// by the kernel side on their first byte or transition, so their bytes are
// counted from the attach on (#142).
type NetworkEBPFCollector struct {
	tracer   *bpf.NetTracer
	pid      int
	resolver *SocketResolver
	ch       chan interface{}
	stop     chan struct{}

	// tput accumulates the target's monotonic byte totals across every
	// connection the map holds, closed ones included (#128). publishLoop-only.
	tput netAccumulator
	// caveat is what this probe could not see, decided by the first bootstrap
	// (#140). Written in start, before Start returns, and read after it.
	caveat string
	// preexisting holds the connections the first bootstrap found: open before
	// the capture (#142). Kept here rather than as a flag in the kernel row
	// because the kernel may adopt the socket — on its first byte after the
	// attach — before the seed gets to write that row, and setting a flag on
	// an existing row would race the kernel's own byte counters. Written in
	// start; read and pruned by publishLoop.
	preexisting map[bpf.NetConnKey]struct{}
}

// Caveat reports what an ACTIVE network probe could not see — pre-existing
// connections it failed to seed — or "" when there is nothing to qualify.
func (c *NetworkEBPFCollector) Caveat() string { return c.caveat }

func NewNetworkEBPFCollector() *NetworkEBPFCollector {
	return &NetworkEBPFCollector{
		// Buffered for the snapshot ticker plus bursty per-event net errors
		// (matches the heap collector's depth); both senders drop on overflow.
		ch:       make(chan interface{}, 64),
		stop:     make(chan struct{}),
		resolver: NewSocketResolver(),
	}
}

func (c *NetworkEBPFCollector) Start(pid int) error { return c.start(bpf.TargetPID(pid), pid) }

// StartCgroup tracks connections across a whole cgroup subtree instead of one
// pid (#94). Implements CgroupTargeter.
//
// The /proc bootstrap is skipped (it needs a pid), so connections that already
// existed when ptop attached only appear once they show some activity. New
// connections are tracked normally.
func (c *NetworkEBPFCollector) StartCgroup(spec string) error {
	return c.start(bpf.TargetCgroup(spec), 0)
}

func (c *NetworkEBPFCollector) start(t bpf.Target, pid int) error {
	tracer, err := bpf.OpenNetTracer(t)
	if err != nil {
		return fmt.Errorf("network eBPF: %w", err)
	}
	c.tracer = tracer
	c.pid = pid
	// Every counter in the map starts at zero after this instant, so the
	// accumulator's first interval runs from here.
	c.tput.at = time.Now()
	// Synchronous bootstrap: populates the map with TCP connections that
	// already exist in /proc/<pid>/net/tcp{,6} before the first snapshot.
	// Without this, a process holding idle keep-alive connections looks like it
	// talks to nobody until one of them moves a byte or changes state.
	// The tables are the TARGET's — ptop may live in another network namespace,
	// where its own /proc/net/tcp holds none of the target's sockets (#140).
	c.resolver.ForPID(pid)
	if pid > 0 {
		c.caveat = c.bootstrapFromProc(true).caveat(pid)
	} else {
		c.caveat = cgroupSeedCaveat
	}
	if tracer.ByteLane == bpf.NetByteLaneKprobe {
		c.caveat = joinCaveats(c.caveat, kprobeLaneCaveat)
	}
	go c.publishLoop()
	// Drain net-error events. tracer is passed explicitly (not read from the
	// field) so Stop()'s `c.tracer = nil` can't race this goroutine; Close()
	// shuts the ring-buffer reader, unblocking NextError with io.EOF.
	go c.readLoop(tracer)
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
	// Re-seed every 5s to catch connections opened since the attach that have
	// neither moved a byte nor changed state — an accepted connection waiting
	// for its first request — so fan_out counts them before they do.
	const reseedEvery = 10 // 10 × 500ms = 5s
	tick := 0
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			tick++
			if tick%reseedEvery == 0 {
				c.bootstrapFromProc(false)
			}
			conns, tput := c.snapshot()
			publish(c.ch, conns)
			publish(c.ch, tput)
		}
	}
}

// readLoop drains the net-error ring buffer, decoding each record into a
// NetError and publishing it on the shared channel. It exits on io.EOF (the
// tracer was closed). A garbled record is logged-by-skip — the stream
// continues. Sends are non-blocking: under backpressure errors are dropped,
// consistent with every other collector.
func (c *NetworkEBPFCollector) readLoop(tracer *bpf.NetTracer) {
	if tracer == nil {
		return
	}
	for {
		rec, err := tracer.NextError()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			continue // transient (short/garbled record) — keep reading
		}
		ne := decodeNetError(time.Now(), rec.Key.DAddr, rec.Key.DPort,
			rec.Key.Family, rec.Kind, rec.Retransmits, rec.DetailNs)
		publish(c.ch, ne)
	}
}

// bootstrapFromProc enumerates /proc/<pid>/fd/, identifies the process's
// socket FDs, resolves their inodes in the target's /proc/<pid>/net/tcp{,6}
// (SocketResolver, #140) and seeds the eBPF net_conn_map with BPF_NOEXIST —
// existing entries are preserved with their real state/RTT/bytes. It returns
// what it managed, which the first call turns into the probe's caveat.
//
// A seeded row has no socket pointer, so it holds no bytes until the kernel
// side adopts the socket — on its first send or receive, or its first state
// change, by matching this 4-tuple (#142). That leaves no gap: a seeded row
// with zero bytes is a connection the target did not use while watched.
//
// atAttach records what this call finds as open before the capture. Only the
// first call can say that; a later one finds connections opened since.
func (c *NetworkEBPFCollector) bootstrapFromProc(atAttach bool) seedReport {
	var rep seedReport
	if c.tracer == nil || c.pid <= 0 {
		return rep
	}
	fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", c.pid))
	if err != nil {
		rep.fdErr = err
		return rep
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
	rep.sockets = len(inodes)
	if len(inodes) == 0 {
		return rep
	}
	// Resolve via SocketResolver. The resolver has a 2s cache, but we call it
	// once here — forces a refresh if stale.
	for inode := range inodes {
		info, ok := c.resolver.Resolve(inode)
		if !ok {
			continue
		}
		rep.resolved++
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
		if c.tracer.SeedConnection(key, info.StateNum) != nil || !atAttach {
			continue
		}
		if c.preexisting == nil {
			c.preexisting = make(map[bpf.NetConnKey]struct{})
		}
		c.preexisting[key] = struct{}{}
	}
	return rep
}

// snapshot returns the ACTIVE connections and the target's cumulative volume.
//
// The two come from one read of the map on purpose. The list drops closed
// connections, which is right — the panel is called Active Connections — but
// their bytes must not drop with them, and by the time a caller has the list
// they are gone. So the accumulator is fed here, from every entry the map
// holds, before the filter (#128).
func (c *NetworkEBPFCollector) snapshot() ([]NetConn, NetThroughputSample) {
	if c.tracer == nil {
		return nil, NetThroughputSample{}
	}
	snaps, err := c.tracer.Stats()
	if err != nil {
		return nil, NetThroughputSample{}
	}

	readings := make([]netByteReading, 0, len(snaps))
	var spent []bpf.NetConnKey
	for _, s := range snaps {
		readings = append(readings, netByteReading{
			Key: netTupleKey(s.SAddr.String(), s.SPort, s.DAddr.String(), s.DPort),
			Tx:  s.TxBytes, Rx: s.RxBytes,
		})
		if s.State == tcpStateCLOSE {
			spent = append(spent, s.Key)
			// The tuple is free for a new connection, which is not pre-existing.
			delete(c.preexisting, s.Key)
		}
	}
	tput := c.tput.observe(readings, time.Now())

	// Prune AFTER accumulating, never before (#133).
	//
	// The kernel never deletes from net_conn_map, so its 4096 slots fill and
	// stay full — measured at twelve seconds under short-lived connections,
	// after which every new connection is refused with -E2BIG and simply does
	// not exist for ptop. Pruning has to happen here rather than in the BPF
	// program because only this side knows when an entry has been CONSUMED.
	//
	// A closed connection is consumed exactly once: its final bytes went into
	// the monotonic totals on the line above, which is what lets the row go
	// without the volume going with it (#128). That ordering is the whole
	// design — deleting in the program at TCP_CLOSE, the obvious fix, would
	// throw those bytes away before anyone read them.
	//
	// Only TCP_CLOSE, which is terminal: sock_to_key is deleted at that
	// transition too, so no further byte can be attributed to the entry.
	if len(spent) > 0 {
		if err := c.tracer.DeleteConns(spent); err != nil {
			fmt.Fprintf(os.Stderr, "network: pruning closed connections: %v\n", err)
		}
	}
	if n, err := c.tracer.InsertFailures(); err == nil {
		tput.DroppedConnections = n
	}

	// Most recent activity first, so rows do not jump around in the terminal.
	// Sorted before conversion: NetConn has no timestamp to sort on, and
	// sorting the converted list by the source's indices (as this once did)
	// compares entries that no longer line up once CLOSE rows are skipped.
	sort.SliceStable(snaps, func(i, j int) bool { return snaps[i].LastNs > snaps[j].LastNs })
	out := make([]NetConn, 0, len(snaps))
	for _, s := range snaps {
		if s.State == tcpStateCLOSE {
			continue
		}
		nc := NetConn{
			Type:    "TCP",
			Remote:  formatNetAddr(s.DAddr.String(), s.DPort, s.Family),
			State:   mapTCPState(s.State),
			Dir:     directionFromBytes(s.TxBytes, s.RxBytes),
			TxBytes: s.TxBytes,
			RxBytes: s.RxBytes,
		}
		_, nc.Preexisting = c.preexisting[s.Key]
		if s.RTTMeasured {
			nc.LatencyMs, nc.RTTMeasured = float64(s.RTTNs)/1e6, true
		}
		out = append(out, nc)
	}
	return out, tput
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
