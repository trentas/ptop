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

type netCheck struct {
	failed bool
}

func (n *netCheck) pass(format string, a ...any) { fmt.Printf("PASS  net:      "+format+"\n", a...) }
func (n *netCheck) fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "FAIL  net:      "+format+"\n", a...)
	n.failed = true
}

// bytesMatch checks a row moved exactly netPayload each way.
func (n *netCheck) bytesMatch(what string, s bpf.NetSnapshot) bool {
	if s.TxBytes != netPayload || s.RxBytes != netPayload {
		n.fail("%s: tx/rx = %d/%d, want %d/%d", what, s.TxBytes, s.RxBytes, netPayload, netPayload)
		return false
	}
	return true
}

func checkNetwork(pid int) bool {
	n := &netCheck{}
	port, stopEcho, err := startEchoPeer()
	if err != nil {
		n.fail("cannot start the peer process: %v", err)
		return false
	}
	defer stopEcho()
	echoAddr := fmt.Sprintf("127.0.0.1:%d", port)

	// A connection that exists before the tracer does (#142).
	pre, err := net.Dial("tcp4", echoAddr)
	if err != nil {
		n.fail("dial the peer: %v", err)
		return false
	}
	defer pre.Close()
	if err := roundTrip(pre); err != nil {
		n.fail("round trip before attach: %v", err)
		return false
	}

	t, err := bpf.OpenNetTracer(bpf.TargetPID(pid))
	if err != nil {
		n.fail("OpenNetTracer: %v", err)
		return false
	}
	defer t.Close()
	fmt.Printf("      network bytes via %s\n", t.ByteLane)

	// 1. Pre-existing: seeded the way the collector seeds it, then used.
	preKey := connKey(pre.LocalAddr(), pre.RemoteAddr())
	if err := t.SeedConnection(preKey, 1); err != nil {
		n.fail("seed: %v", err)
	}
	if err := roundTrip(pre); err != nil {
		n.fail("round trip on the seeded connection: %v", err)
	}
	if s, ok := findConn(t, preKey); !ok {
		n.fail("pre-existing connection: no row")
	} else if n.bytesMatch("pre-existing connection", s) {
		n.pass("pre-existing connection: %d bytes each way, measured from the attach (#142)", netPayload)
	}

	// 2. Active open: keyed by the real source port, handshake timed.
	act, err := net.Dial("tcp4", echoAddr)
	if err != nil {
		n.fail("dial the peer: %v", err)
		return false
	}
	actKey := connKey(act.LocalAddr(), act.RemoteAddr())
	if err := roundTrip(act); err != nil {
		n.fail("round trip on a new connection: %v", err)
	}
	s, ok := findConn(t, actKey)
	switch {
	case !ok:
		n.fail("connect(): no row under the real source port")
	case !s.RTTMeasured:
		n.fail("connect(): handshake RTT not measured")
	case n.bytesMatch("connect()", s):
		n.pass("connect(): handshake %v, %d bytes each way", time.Duration(s.RTTNs), netPayload)
	}
	zero := actKey
	zero.SPort = 0
	if _, ok := findConn(t, zero); ok {
		n.fail("connect(): a row keyed with source port 0 — SYN_SENT was keyed before the port existed")
	}

	// Once owned, a socket is followed to CLOSE whatever context runs it (#133).
	_ = act.Close()
	closed := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if s, ok := findConn(t, actKey); ok && s.State == 7 {
			closed = true
			break
		}
	}
	if closed {
		n.pass("connect(): CLOSE observed, so the row can be pruned")
	} else {
		n.fail("connect(): never reached CLOSE — the row would never be pruned")
	}

	// 3. Passive open: a server's accepted connection, and the peer's socket
	// must NOT be credited to us even though our close() runs its FIN handling.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		n.fail("listen: %v", err)
		return false
	}
	defer ln.Close()
	client := peerCmd(fmt.Sprintf("client:%s:%d", ln.Addr(), netPayload))
	if err := client.Start(); err != nil {
		n.fail("start the client process: %v", err)
		return false
	}
	acc, err := ln.Accept()
	if err != nil {
		n.fail("accept: %v", err)
		_ = client.Process.Kill()
		return false
	}
	accKey := connKey(acc.LocalAddr(), acc.RemoteAddr())
	peerKey := connKey(acc.RemoteAddr(), acc.LocalAddr())
	_, rerr := io.ReadFull(acc, make([]byte, netPayload))
	_, werr := acc.Write(make([]byte, netPayload))
	_ = acc.Close()
	_ = client.Wait()
	if rerr != nil || werr != nil {
		n.fail("accepted connection I/O: %v / %v", rerr, werr)
	}
	s, ok = findConn(t, accKey)
	switch {
	case !ok:
		n.fail("accept(): no row — a server's connections are invisible (#135)")
	case s.RTTMeasured:
		n.fail("accept(): an RTT was reported for a handshake nobody timed")
	case n.bytesMatch("accept()", s):
		n.pass("accept(): %d bytes each way, RTT reported as not measured", netPayload)
	}
	if _, ok := findConn(t, peerKey); ok {
		n.fail("the peer process's socket was credited to this process (#135)")
	} else {
		n.pass("the peer process's socket was not credited to this process")
	}
	return !n.failed
}
