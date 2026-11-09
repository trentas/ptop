//go:build linux && ebpf

package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/trentas/ptop/internal/bpf"
)

// The network phase checks the claims network.bpf.c rests on (#135, #142),
// each against a peer in ANOTHER process — the shape every one of the old
// failures needed. On loopback the softirq that processes a packet runs in the
// sender's context, so a peer inside this process would make `current` the
// target every time and pass a filter that is wrong.
//
// The peer is this binary re-executed with peerEnv set.
const peerEnv = "PTOP_SELFTEST_PEER"

// netPayload is what each check moves in each direction. Small enough for one
// loopback round trip, so a byte counter has no excuse to be off by any.
const netPayload = 32 << 10

// runPeer is the child side: "echo" serves an echo on a loopback port it
// prints, "client:<addr>:<n>" sends n bytes to addr and reads until EOF.
func runPeer(spec string) {
	switch {
	case spec == "echo":
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			os.Exit(1)
		}
		fmt.Println(ln.Addr().(*net.TCPAddr).Port)
		for {
			c, err := ln.Accept()
			if err != nil {
				os.Exit(0)
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	case strings.HasPrefix(spec, "client:"):
		rest := strings.TrimPrefix(spec, "client:")
		i := strings.LastIndexByte(rest, ':')
		n, _ := strconv.Atoi(rest[i+1:])
		c, err := net.Dial("tcp4", rest[:i])
		if err != nil {
			os.Exit(1)
		}
		_, _ = c.Write(make([]byte, n))
		_, _ = io.Copy(io.Discard, c)
		_ = c.Close()
		os.Exit(0)
	}
	os.Exit(2)
}

func peerCmd(spec string) *exec.Cmd {
	cmd := exec.Command("/proc/self/exe")
	cmd.Env = append(os.Environ(), peerEnv+"="+spec)
	cmd.Stderr = os.Stderr
	return cmd
}

// startEchoPeer starts the echo child and returns its port and a stop func.
func startEchoPeer() (int, func(), error) {
	cmd := peerCmd("echo")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return 0, nil, err
	}
	if err := cmd.Start(); err != nil {
		return 0, nil, err
	}
	stop := func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		stop()
		return 0, nil, fmt.Errorf("echo peer: %w", err)
	}
	port, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		stop()
		return 0, nil, fmt.Errorf("echo peer port %q: %w", line, err)
	}
	return port, stop, nil
}

// connKey is the tracer's key for a connection seen from this side.
func connKey(local, remote net.Addr) bpf.NetConnKey {
	l, r := local.(*net.TCPAddr), remote.(*net.TCPAddr)
	k := bpf.NetConnKey{SPort: uint16(l.Port), DPort: uint16(r.Port), Family: 2}
	copy(k.SAddr[:], l.IP.To4())
	copy(k.DAddr[:], r.IP.To4())
	return k
}

// roundTrip writes netPayload bytes and reads them back from an echo peer.
func roundTrip(c net.Conn) error {
	if _, err := c.Write(make([]byte, netPayload)); err != nil {
		return err
	}
	_, err := io.ReadFull(c, make([]byte, netPayload))
	return err
}

func findConn(t *bpf.NetTracer, k bpf.NetConnKey) (bpf.NetSnapshot, bool) {
	snaps, _ := t.Stats()
	for _, s := range snaps {
		if s.Key == k {
			return s, true
		}
	}
	return bpf.NetSnapshot{}, false
}

// bytesMatch grades a row as having moved exactly netPayload each way.
func bytesMatch(g *grader, claim string, s bpf.NetSnapshot) bool {
	return g.check("net", claim, s.TxBytes == netPayload && s.RxBytes == netPayload,
		fmt.Sprintf("tx/rx %d/%d bytes", netPayload, netPayload),
		fmt.Sprintf("%d/%d", s.TxBytes, s.RxBytes))
}

// row renders whether a lookup found a row.
func row(found bool) string {
	if found {
		return "a row"
	}
	return "none"
}

// rtt renders a row's handshake time, or says it was not measured.
func rtt(s bpf.NetSnapshot) string {
	if !s.RTTMeasured {
		return "not measured"
	}
	return time.Duration(s.RTTNs).String()
}

func checkNetwork(g *grader, pid int) {
	port, stopEcho, err := startEchoPeer()
	if err != nil {
		g.broken("net", "peer process", err)
		return
	}
	defer stopEcho()
	echoAddr := fmt.Sprintf("127.0.0.1:%d", port)

	// A connection that exists before the tracer does (#142).
	pre, err := net.Dial("tcp4", echoAddr)
	if err != nil {
		g.broken("net", "dial the peer", err)
		return
	}
	defer pre.Close()
	if err := roundTrip(pre); err != nil {
		g.broken("net", "round trip before attach", err)
		return
	}

	t, err := bpf.OpenNetTracer(bpf.TargetPID(pid))
	if err != nil {
		g.broken("net", "attach", fmt.Errorf("OpenNetTracer: %w", err))
		return
	}
	defer t.Close()
	g.note("net", "bytes via %s", t.ByteLane)

	// 1. Pre-existing: seeded the way the collector seeds it, then used.
	preKey := connKey(pre.LocalAddr(), pre.RemoteAddr())
	if err := t.SeedConnection(preKey, 1); err != nil {
		g.broken("net", "seed the pre-existing connection", err)
	}
	if err := roundTrip(pre); err != nil {
		g.broken("net", "round trip on the seeded connection", err)
	}
	if s, ok := findConn(t, preKey); g.check("net", "pre-existing connection has a row (#142)", ok, "a row", row(ok)) {
		bytesMatch(g, "pre-existing connection, bytes since the attach", s)
	}

	// 2. Active open: keyed by the real source port, handshake timed.
	act, err := net.Dial("tcp4", echoAddr)
	if err != nil {
		g.broken("net", "dial the peer", err)
		return
	}
	actKey := connKey(act.LocalAddr(), act.RemoteAddr())
	if err := roundTrip(act); err != nil {
		g.broken("net", "round trip on a new connection", err)
	}
	if s, ok := findConn(t, actKey); g.check("net", "connect(): row under the real source port", ok, "a row", row(ok)) {
		g.check("net", "connect(): handshake RTT", s.RTTMeasured, "measured", rtt(s))
		bytesMatch(g, "connect(), bytes", s)
	}
	zero := actKey
	zero.SPort = 0
	_, keyedZero := findConn(t, zero)
	g.check("net", "connect(): no row keyed on source port 0 (SYN_SENT before the port exists)", !keyedZero,
		"none", row(keyedZero))

	// Once owned, a socket is followed to CLOSE whatever context runs it (#133).
	_ = act.Close()
	const tcpClose = 7 // TCP_CLOSE in the kernel's enum
	closed, last := false, "no row"
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if s, ok := findConn(t, actKey); ok {
			last = fmt.Sprintf("state %d", s.State)
			if s.State == tcpClose {
				closed = true
				break
			}
		}
	}
	g.check("net", "connect(): CLOSE within 3s, so the row can be pruned", closed,
		fmt.Sprintf("state %d (CLOSE)", tcpClose), last)

	// 3. Passive open: a server's accepted connection, and the peer's socket
	// must NOT be credited to us even though our close() runs its FIN handling.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		g.broken("net", "listen", err)
		return
	}
	defer ln.Close()
	client := peerCmd(fmt.Sprintf("client:%s:%d", ln.Addr(), netPayload))
	if err := client.Start(); err != nil {
		g.broken("net", "start the client process", err)
		return
	}
	acc, err := ln.Accept()
	if err != nil {
		g.broken("net", "accept", err)
		_ = client.Process.Kill()
		return
	}
	accKey := connKey(acc.LocalAddr(), acc.RemoteAddr())
	peerKey := connKey(acc.RemoteAddr(), acc.LocalAddr())
	_, rerr := io.ReadFull(acc, make([]byte, netPayload))
	_, werr := acc.Write(make([]byte, netPayload))
	_ = acc.Close()
	_ = client.Wait()
	if rerr != nil || werr != nil {
		g.broken("net", "accepted connection I/O", fmt.Errorf("read: %v, write: %v", rerr, werr))
	}
	if s, ok := findConn(t, accKey); g.check("net", "accept(): the server's connection has a row (#135)", ok, "a row", row(ok)) {
		g.check("net", "accept(): handshake RTT", !s.RTTMeasured, "not measured (nobody timed it)", rtt(s))
		bytesMatch(g, "accept(), bytes", s)
	}
	_, peerCredited := findConn(t, peerKey)
	g.check("net", "the peer process's socket is not credited to this one (#135)", !peerCredited,
		"none", row(peerCredited))
}
