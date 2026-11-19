//go:build linux && ebpf

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trentas/ptop/internal/report"
	"github.com/trentas/ptop/internal/serve"
	"github.com/trentas/ptop/pkg/collector"
	pb "github.com/trentas/ptop/pkg/streampb"
)

// ─── netorigin: who opened a connection, and which one it is (#195) ────────
//
// The consumer this was found by told a service's callers from its
// dependencies with `dir`, a byte-volume arrow, and told its sockets apart by
// `fd`, which the eBPF lane published as 0 for every one. So this case plants
// what the arrow gets wrong and grades what reaches the wire: the report of a
// --for window, through the collector, the mapper and the report builder.
//
//   - Three connections the target connect()s to one peer: idle, downloading
//     (the arrow read "←", a caller), uploading. All three are "connected",
//     and they are three rows: one remote, three locals.
//   - Three the target accept()s from clients in other processes: idle,
//     receiving, sending (the arrow read "→", a dependency). All "accepted".
//     The busy two through the kernel, which noted their passive opens and
//     owns them at their first byte. The idle one through the listener rule,
//     since nothing proves the target owns it until the collector's 5-second
//     rescan finds it in the fds: hence a window that outlasts a rescan.
//   - Two open before the capture. The one accepted on the target's listener
//     is "accepted" by the listener rule; the one it connected is unknown,
//     because nothing saw that connect() and the rule has no answer for it.
//   - A listener is not a row: the one open before the capture, which the
//     seed finds, nor one opened under the probe, which the program owns.
//   - No row carries an fd: the lane has none to give.
//
// The bytes move after the window's first reading, so each row's are exact,
// which is also what shows the busy ones were busy.

// plantedConn is one connection the case planted, and what the report must
// say about it.
type plantedConn struct {
	name   string
	conn   net.Conn
	origin pb.ConnOrigin
	tx, rx uint64
}

func (p plantedConn) local() string  { return p.conn.LocalAddr().String() }
func (p plantedConn) remote() string { return p.conn.RemoteAddr().String() }

func checkNetOrigin(g *grader, pid int) {
	// Long enough for the collector's first rescan (5s after its start) to
	// land inside it, with the bootstrap and the plants before the window.
	const window = 7 * time.Second
	const connected, accepted, unknown = pb.ConnOrigin_CONN_ORIGIN_CONNECTED,
		pb.ConnOrigin_CONN_ORIGIN_ACCEPTED, pb.ConnOrigin_CONN_ORIGIN_UNSPECIFIED

	port, stopPump, err := startServingPeer("pump")
	if err != nil {
		g.broken("netorigin", "peer process", err)
		return
	}
	defer stopPump()
	pumpAddr := fmt.Sprintf("127.0.0.1:%d", port)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		g.broken("netorigin", "listen", err)
		return
	}
	defer ln.Close()

	var clients []*exec.Cmd
	var planted []plantedConn
	defer func() {
		for _, p := range planted {
			_ = p.conn.Close()
		}
		for _, c := range clients {
			_ = c.Process.Kill()
			_ = c.Wait()
		}
	}()
	// acceptFrom starts a client process that sends n bytes and then reads
	// until EOF, and accepts its connection. One at a time, so each accepted
	// connection is known to be that client's.
	acceptFrom := func(n int) (net.Conn, error) {
		cmd := peerCmd(fmt.Sprintf("client:%s:%d", ln.Addr(), n))
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		clients = append(clients, cmd)
		return ln.Accept()
	}
	plant := func(name string, origin pb.ConnOrigin, open func() (net.Conn, error)) bool {
		c, err := open()
		if err != nil {
			g.broken("netorigin", "open "+name, err)
			return false
		}
		planted = append(planted, plantedConn{name: name, conn: c, origin: origin})
		return true
	}
	dialPump := func() (net.Conn, error) { return net.Dial("tcp4", pumpAddr) }

	// Before the capture.
	if !plant("connected before the capture", unknown, dialPump) ||
		!plant("accepted before the capture", accepted, func() (net.Conn, error) { return acceptFrom(0) }) {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	feed := collector.StartFeed(ctx, collector.SetConfig{
		PID:     pid,
		Disable: onlySubsystems(collector.SubsystemNetwork),
		ListCap: report.CollectorListCap,
	})
	defer feed.Stop()

	// A listener opened under the probe: the program owns it on the spot (its
	// listen() is evidence), where the one above is only in the fd table.
	ln2, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		g.broken("netorigin", "listen", err)
		return
	}
	defer ln2.Close()

	// During it, before the window opens: the opens, which is what the
	// program has to see.
	const n = netPayload
	if !plant("connected, idle", connected, dialPump) ||
		!plant("connected, downloading", connected, dialPump) ||
		!plant("connected, uploading", connected, dialPump) ||
		!plant("accepted, idle", accepted, func() (net.Conn, error) { return acceptFrom(0) }) ||
		!plant("accepted, receiving", accepted, func() (net.Conn, error) { return acceptFrom(n) }) ||
		!plant("accepted, sending", accepted, func() (net.Conn, error) { return acceptFrom(0) }) {
		return
	}
	byName := make(map[string]*plantedConn, len(planted))
	for i := range planted {
		byName[planted[i].name] = &planted[i]
	}

	var (
		opened       atomic.Bool
		once         sync.Once
		firstReading = make(chan struct{})
	)
	h := feed.Bus.AddHandler(func(v any) {
		if _, ok := v.([]collector.NetConn); ok && opened.Load() {
			once.Do(func() { close(firstReading) })
		}
	})
	defer feed.Bus.RemoveHandler(h)

	started := make(chan struct{})
	res := make(chan captureResult, 1)
	go func() {
		r, err := serve.Capture(ctx, serve.TargetPID(pid), feed, nil, serve.CaptureOptions{
			For: window, TopN: report.MaxTopN, ListCap: report.CollectorListCap, Started: started,
		})
		res <- captureResult{r, err}
	}()
	select {
	case <-started:
	case x := <-res:
		g.broken("netorigin", "open the window", x.err)
		return
	case <-time.After(10 * time.Second):
		g.broken("netorigin", "open the window", errors.New("still not open after 10s"))
		return
	}
	opened.Store(true)
	select {
	case <-firstReading:
	case <-time.After(3 * time.Second):
		g.broken("netorigin", "the window's first reading", errors.New("no connection list within 3s of the window opening"))
		return
	}

	// The bytes, after the baseline.
	if err := moveBytes(byName); err != nil {
		g.broken("netorigin", "move the planted bytes", err)
		return
	}

	var x captureResult
	select {
	case x = <-res:
	case <-time.After(window + 10*time.Second):
		g.broken("netorigin", "close the window", errors.New("Capture did not return"))
		return
	}
	if x.err != nil {
		g.broken("netorigin", "close the window", x.err)
		return
	}
	conns := x.r.GetNetwork().GetConns()

	rowOf := func(p *plantedConn) *pb.NetConn {
		for _, c := range conns {
			if c.GetLocal() == p.local() && c.GetRemote() == p.remote() {
				return c
			}
		}
		return nil
	}
	for i := range planted {
		p := &planted[i]
		c := rowOf(p)
		got := "a row"
		if c == nil {
			got = rowList(conns)
		}
		if !g.check("netorigin", p.name+": a row of its own", c != nil,
			fmt.Sprintf("%s → %s", p.local(), p.remote()), got) {
			continue
		}
		g.check("netorigin", p.name+": origin", c.GetOrigin() == p.origin, p.origin.String(),
			fmt.Sprintf("%s (dir %s)", c.GetOrigin(), c.GetDir()))
		g.check("netorigin", p.name+": bytes in the window", c.GetTxBytes() == p.tx && c.GetRxBytes() == p.rx,
			fmt.Sprintf("tx/rx %d/%d", p.tx, p.rx), fmt.Sprintf("%d/%d", c.GetTxBytes(), c.GetRxBytes()))
	}

	// One peer, several connections: told apart by their own endpoint.
	locals := make(map[string]bool)
	for _, c := range conns {
		if c.GetRemote() == pumpAddr {
			locals[c.GetLocal()] = true
		}
	}
	g.check("netorigin", "four connections to one peer are four rows", len(locals) == 4,
		fmt.Sprintf("4 distinct locals to %s", pumpAddr), fmt.Sprint(len(locals)))

	var listenerRows, withFD []string
	for _, c := range conns {
		if c.GetState() == "LISTEN" || strings.HasSuffix(c.GetRemote(), ":0") {
			listenerRows = append(listenerRows, c.GetLocal()+"→"+c.GetRemote()+" "+c.GetState())
		}
		if c.Fd != nil {
			withFD = append(withFD, fmt.Sprintf("%s fd %d", c.GetLocal(), c.GetFd()))
		}
	}
	g.check("netorigin", "a listener is not a connection, from before the capture or during it", len(listenerRows) == 0, "no row",
		fmt.Sprint(listenerRows))
	g.check("netorigin", "no fd on a lane that has none", len(withFD) == 0, "absent on every row",
		fmt.Sprint(withFD))
}

// moveBytes plants the busy connections' traffic and records what each moved.
func moveBytes(byName map[string]*plantedConn) error {
	const n = netPayload
	var hdr [8]byte

	// Downloading: ask the pump for n bytes.
	down := byName["connected, downloading"]
	binary.BigEndian.PutUint64(hdr[:], n)
	if _, err := down.conn.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(down.conn, make([]byte, n)); err != nil {
		return err
	}
	down.tx, down.rx = 8, n

	// Uploading: ask for nothing, send n.
	up := byName["connected, uploading"]
	binary.BigEndian.PutUint64(hdr[:], 0)
	if _, err := up.conn.Write(append(hdr[:], make([]byte, n)...)); err != nil {
		return err
	}
	up.tx = 8 + n

	// Receiving: the client sent n when it connected; read them now.
	recv := byName["accepted, receiving"]
	if _, err := io.ReadFull(recv.conn, make([]byte, n)); err != nil {
		return err
	}
	recv.rx = n

	// Sending: the client reads until EOF.
	send := byName["accepted, sending"]
	if _, err := send.conn.Write(make([]byte, n)); err != nil {
		return err
	}
	send.tx = n
	return nil
}

func rowList(conns []*pb.NetConn) string {
	rows := make([]string, 0, len(conns))
	for _, c := range conns {
		rows = append(rows, c.GetLocal()+"→"+c.GetRemote())
	}
	return fmt.Sprintf("%d rows: %s", len(rows), strings.Join(rows, ", "))
}
