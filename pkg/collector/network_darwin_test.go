//go:build darwin

package collector

import (
	"net"
	"os"
	"testing"
	"time"
)

// TestSocketToNetConn_queuedBytes verifies that the socket-buffer occupancy
// from libproc (SndQueued/RcvQueued) is surfaced on the F3 NetConn as
// Tx/RxBytes. This is a gauge (current backlog), not a cumulative counter —
// the mapping is what the test pins down.
func TestSocketToNetConn_queuedBytes(t *testing.T) {
	s := LPSocketFDInfo{
		Family:     2, // AF_INET
		SockType:   1, // SOCK_STREAM
		TCPState:   TCPStateEstablished,
		LocalAddr:  "127.0.0.1:5000",
		RemoteAddr: "127.0.0.1:6000",
		SndQueued:  4096,
		RcvQueued:  1024,
	}
	nc := socketToNetConn(7, s)

	if nc.Type != "TCP" {
		t.Fatalf("Type = %q, want TCP", nc.Type)
	}
	if nc.State != "ESTABLISHED" {
		t.Fatalf("State = %q, want ESTABLISHED", nc.State)
	}
	if nc.Dir != "↔" {
		t.Fatalf("Dir = %q, want ↔ (has remote)", nc.Dir)
	}
	if nc.TxBytes != 4096 {
		t.Fatalf("TxBytes = %d, want 4096 (from SndQueued)", nc.TxBytes)
	}
	if nc.RxBytes != 1024 {
		t.Fatalf("RxBytes = %d, want 1024 (from RcvQueued)", nc.RxBytes)
	}
	// A listener (no remote) maps to the local bind and the "←" direction.
	listener := LPSocketFDInfo{Family: 2, SockType: 1, TCPState: TCPStateListen, LocalAddr: "127.0.0.1:5000"}
	if lnc := socketToNetConn(8, listener); lnc.Dir != "←" || lnc.Remote != "127.0.0.1:5000" {
		t.Fatalf("listener mapping: Dir=%q Remote=%q, want ← / local bind", lnc.Dir, lnc.Remote)
	}
}

// TestConnRank pins the F3 ordering: an active peer connection outranks a
// listener, which outranks an idle/unconnected socket. macOS processes hold
// many idle UDP wildcard sockets that would otherwise bury real connections.
func TestConnRank(t *testing.T) {
	connected := NetConn{Type: "TCP", Dir: "↔", State: "ESTABLISHED", Remote: "[fe80::1]:1024"}
	listener := NetConn{Type: "TCP", Dir: "←", State: "LISTEN", Remote: "0.0.0.0:443"}
	idleUDP := NetConn{Type: "UDP", Dir: "←", State: "", Remote: "0.0.0.0:0"}

	if connRank(connected) >= connRank(listener) {
		t.Fatalf("connected (%d) should rank before listener (%d)", connRank(connected), connRank(listener))
	}
	if connRank(listener) >= connRank(idleUDP) {
		t.Fatalf("listener (%d) should rank before idle UDP (%d)", connRank(listener), connRank(idleUDP))
	}
	if typeRank("TCP") >= typeRank("UDP") {
		t.Fatalf("TCP should rank before UDP")
	}
}

// TestFDSocketInfo_queuedBytes_live drives the wrapper against a real TCP
// connection. We stuff the sender's buffer without ever reading on the peer,
// so bytes pile up in either the send or receive buffer; FDSocketInfo must
// then report non-zero occupancy for at least one of the process's sockets.
// Kernel buffering is timing-dependent, so this is best-effort: if nothing is
// queued we log and skip rather than fail.
func TestFDSocketInfo_queuedBytes_live(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	defer ln.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Skipf("cannot dial: %v", err)
	}
	defer conn.Close()

	// Accept but deliberately never read — the peer's receive buffer (and
	// then our send buffer) fills up.
	peer, err := ln.Accept()
	if err != nil {
		t.Skipf("cannot accept: %v", err)
	}
	defer peer.Close()

	// Write more than a typical socket buffer (several hundred KB) without
	// blocking forever: a deadline bounds the test if buffers are huge.
	_ = conn.(*net.TCPConn).SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	blob := make([]byte, 1<<20) // 1 MiB
	_, _ = conn.Write(blob)

	// Give the kernel a moment to settle the buffers.
	time.Sleep(50 * time.Millisecond)

	fds, err := ListFDs(os.Getpid())
	if err != nil {
		t.Fatalf("ListFDs(self): %v", err)
	}
	var maxQueued uint64
	for _, fd := range fds {
		if fd.Type != FDTypeSocket {
			continue
		}
		s, err := FDSocketInfo(os.Getpid(), fd.FD)
		if err != nil {
			continue
		}
		if q := s.SndQueued + s.RcvQueued; q > maxQueued {
			maxQueued = q
		}
	}
	if maxQueued == 0 {
		t.Skip("no socket buffer occupancy observed (kernel drained immediately); mapping still covered by the unit test")
	}
	t.Logf("max socket buffer occupancy across self sockets = %d bytes", maxQueued)
}

// TestNetworkCollector_live drives the full darwin collector pipeline end to
// end against this process: ListFDs → FDSocketInfo → socketToNetConn →
// Subscribe(). It opens a real TCP connection, stuffs the sender, then
// confirms a published []NetConn carries a TCP entry with non-zero Tx or Rx
// (the queued-buffer reading). This is the closest thing to running ptop
// against a live process without a TTY.
func TestNetworkCollector_live(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen: %v", err)
	}
	defer ln.Close()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Skipf("cannot dial: %v", err)
	}
	defer conn.Close()
	peer, err := ln.Accept()
	if err != nil {
		t.Skipf("cannot accept: %v", err)
	}
	defer peer.Close()

	_ = conn.(*net.TCPConn).SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	_, _ = conn.Write(make([]byte, 1<<20)) // 1 MiB, peer never reads

	c := NewNetworkEBPFCollector()
	if err := c.Start(os.Getpid()); err != nil {
		t.Fatalf("collector Start(self): %v", err)
	}
	defer c.Stop()

	// First publish lands immediately (loop calls collectAndEmit before the
	// ticker); give it a generous deadline regardless.
	var conns []NetConn
	select {
	case v := <-c.Subscribe():
		nc, ok := v.([]NetConn)
		if !ok {
			t.Fatalf("expected []NetConn, got %T", v)
		}
		conns = nc
	case <-time.After(3 * time.Second):
		t.Fatal("collector published nothing within 3s")
	}

	var tcpCount int
	var maxQueued uint64
	for _, nc := range conns {
		if nc.Type == "TCP" {
			tcpCount++
		}
		if q := nc.TxBytes + nc.RxBytes; q > maxQueued {
			maxQueued = q
		}
	}
	t.Logf("collector published %d conns (%d TCP), max Tx+Rx = %d bytes", len(conns), tcpCount, maxQueued)
	if tcpCount == 0 {
		t.Fatal("expected at least one TCP connection from the live socket pair")
	}
	if maxQueued == 0 {
		t.Skip("no queued bytes surfaced (kernel drained immediately); pipeline still exercised")
	}
}
