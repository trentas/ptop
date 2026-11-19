package collector

import (
	"net"
	"testing"

	"github.com/trentas/ptop/internal/bpf"
)

func v4row(saddr string, sport uint16, daddr string, dport uint16, state uint32) bpf.NetSnapshot {
	return bpf.NetSnapshot{
		Family: 2, State: state,
		SAddr: net.ParseIP(saddr).To4(), SPort: sport,
		DAddr: net.ParseIP(daddr).To4(), DPort: dport,
	}
}

// A listener is not a connection (#195). Its row's remote is 0.0.0.0:0, and a
// consumer counted it as a peer. A closed connection is not one either, any
// more.
func TestNetConnFromRowDropsListenersAndClosed(t *testing.T) {
	for _, st := range []uint32{tcpStateLISTEN, tcpStateCLOSE} {
		if nc, ok := netConnFromRow(v4row("0.0.0.0", 8080, "0.0.0.0", 0, st), false, false); ok {
			t.Errorf("state %s published as %+v, want no row", mapTCPState(st), nc)
		}
	}
	for _, st := range []uint32{tcpStateESTABLISHED, tcpStateSYN_SENT, tcpStateCLOSE_WAIT, tcpStateTIME_WAIT} {
		if _, ok := netConnFromRow(v4row("10.0.0.9", 40000, "10.0.0.1", 443, st), false, false); !ok {
			t.Errorf("state %s dropped, want a row", mapTCPState(st))
		}
	}
}

// The origin is who opened the connection, whatever its bytes did: the arrow
// moves with the byte ratio and must not decide it (#195).
func TestNetConnFromRowOrigin(t *testing.T) {
	for _, tc := range []struct {
		name           string
		origin         bpf.NetOrigin
		seenOnListener bool
		tx, rx         uint64
		want, wantDir  string
	}{
		// A client downloading: the old arrow read it as a caller.
		{"connect, downloading", bpf.NetOriginConnected, false, 100, 64 << 10, ConnOriginConnected, "←"},
		{"connect, idle", bpf.NetOriginConnected, false, 0, 0, ConnOriginConnected, "↔"},
		// A server pushing a response: the old arrow read it as a dependency.
		{"accept, uploading", bpf.NetOriginAccepted, false, 64 << 10, 100, ConnOriginAccepted, "→"},
		{"accept, idle", bpf.NetOriginAccepted, false, 0, 0, ConnOriginAccepted, "↔"},
		{"older than the capture, on a listener", bpf.NetOriginUnknown, true, 0, 0, ConnOriginAccepted, "↔"},
		{"older than the capture, elsewhere", bpf.NetOriginUnknown, false, 64 << 10, 0, "", "→"},
		// The program saw the connect; the rule is a rule, the open a measurement.
		{"connect beats the listener rule", bpf.NetOriginConnected, true, 0, 0, ConnOriginConnected, "↔"},
	} {
		s := v4row("10.0.0.9", 8080, "10.0.0.1", 51000, tcpStateESTABLISHED)
		s.Origin, s.TxBytes, s.RxBytes = tc.origin, tc.tx, tc.rx
		nc, ok := netConnFromRow(s, false, tc.seenOnListener)
		if !ok {
			t.Fatalf("%s: no row", tc.name)
		}
		if nc.Origin != tc.want || nc.Dir != tc.wantDir {
			t.Errorf("%s: origin %q dir %s, want %q and %s", tc.name, nc.Origin, nc.Dir, tc.want, tc.wantDir)
		}
	}
}

// Two connections to one peer differ in their own endpoint, and the eBPF lane
// knows no fd (#195).
func TestNetConnFromRowIdentity(t *testing.T) {
	a, _ := netConnFromRow(v4row("10.0.0.9", 40000, "10.0.0.1", 5432, tcpStateESTABLISHED), false, false)
	b, _ := netConnFromRow(v4row("10.0.0.9", 40001, "10.0.0.1", 5432, tcpStateESTABLISHED), false, false)
	if a.Remote != b.Remote || a.Local == b.Local {
		t.Errorf("local %s / %s to %s / %s: want one remote and two locals", a.Local, b.Local, a.Remote, b.Remote)
	}
	if a.Local != "10.0.0.9:40000" || a.Remote != "10.0.0.1:5432" {
		t.Errorf("endpoints %s → %s", a.Local, a.Remote)
	}
	if a.FDKnown {
		t.Errorf("FDKnown on the eBPF lane, which never sees a descriptor")
	}
	v6 := bpf.NetSnapshot{Family: 10, State: tcpStateESTABLISHED,
		SAddr: net.ParseIP("fd00::9"), SPort: 40000, DAddr: net.ParseIP("fd00::1"), DPort: 443}
	if c, _ := netConnFromRow(v6, false, false); c.Local != "[fd00::9]:40000" || c.Remote != "[fd00::1]:443" {
		t.Errorf("IPv6 endpoints %s → %s", c.Local, c.Remote)
	}
}

func endpoint(family uint16, ip string, port uint16) netEndpoint {
	e := netEndpoint{family: family, port: port}
	if family == 2 {
		copy(e.addr[:], net.ParseIP(ip).To4())
	} else {
		copy(e.addr[:], net.ParseIP(ip).To16())
	}
	return e
}

// An accepted connection is its listener's child: same family, same port, and
// an address the listener covers.
func TestListensOn(t *testing.T) {
	listeners := []netEndpoint{
		endpoint(2, "0.0.0.0", 8080),    // every IPv4 address
		endpoint(2, "127.0.0.1", 9090),  // loopback only
		endpoint(10, "::", 8443),        // dual stack: IPv6 and v4-mapped
		endpoint(10, "fd00::9", 7070),   // one IPv6 address
		endpoint(10, "::", 8080),        // IPv6 beside the IPv4 :8080 (V6ONLY)
		endpoint(2, "10.0.0.9", 0xffff), // a high port, to show the port is compared
	}
	for _, tc := range []struct {
		name  string
		local netEndpoint
		want  bool
	}{
		{"on the IPv4 wildcard", endpoint(2, "10.0.0.9", 8080), true},
		{"on the loopback listener", endpoint(2, "127.0.0.1", 9090), true},
		{"another address, same port as a bound listener", endpoint(2, "10.0.0.9", 9090), false},
		{"v4-mapped, on the dual-stack listener", endpoint(10, "::ffff:10.0.0.9", 8443), true},
		{"IPv4 family on an IPv6-only port", endpoint(2, "10.0.0.9", 8443), false},
		{"on the one IPv6 address", endpoint(10, "fd00::9", 7070), true},
		{"another IPv6 address", endpoint(10, "fd00::8", 7070), false},
		{"an ephemeral port", endpoint(2, "10.0.0.9", 40000), false},
	} {
		if got := listensOn(listeners, tc.local); got != tc.want {
			t.Errorf("%s: listensOn = %v, want %v", tc.name, got, tc.want)
		}
	}
	if listensOn(nil, endpoint(2, "10.0.0.9", 8080)) {
		t.Error("no listeners: want false")
	}
}
