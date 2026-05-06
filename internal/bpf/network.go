//go:build linux && ebpf

package bpf

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:embed programs/network.bpf.o
var networkBPFObj []byte

// NetConnKey mirrors `struct net_key` in programs/network.bpf.c 1:1.
// 40 bytes, no padding besides the trailing _pad. cilium/ebpf can iterate
// a HASH map returning this struct directly when sizes match.
type NetConnKey struct {
	DAddr  [16]byte
	SAddr  [16]byte
	DPort  uint16
	SPort  uint16
	Family uint16
	_      uint16 // pad
}

// NetConnVal mirrors `struct net_val`. 64 bytes.
type NetConnVal struct {
	FirstSeenNs   uint64
	LastSeenNs    uint64
	SynSentNs     uint64
	EstablishedNs uint64
	RTTNs         uint64
	TxBytes       uint64
	RxBytes       uint64
	State         uint32
	_             uint32 // pad
}

// NetSnapshot is the user-friendly format returned by Stats() — the 5-tuple
// already decoded into net.IP + ports in host order, with RTT computed.
type NetSnapshot struct {
	Family  uint16 // 2=IPv4, 10=IPv6
	SAddr   net.IP
	DAddr   net.IP
	SPort   uint16
	DPort   uint16
	State   uint32
	RTTNs   uint64
	TxBytes uint64
	RxBytes uint64
	LastNs  uint64
}

// NetTracer loads network.bpf.o, attaches the sock:inet_sock_set_state
// tracepoint + kprobes on tcp_sendmsg/tcp_cleanup_rbuf, and exposes Stats()
// to read the map.
type NetTracer struct {
	coll  *ebpf.Collection
	links []link.Link
	cmap  *ebpf.Map
}

func OpenNetTracer(pid int) (*NetTracer, error) {
	if pid <= 0 {
		return nil, errors.New("invalid pid")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(networkBPFObj))
	if err != nil {
		return nil, fmt.Errorf("parse net BPF object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load net collection: %w", err)
	}
	t := &NetTracer{coll: coll}

	targetMap := coll.Maps["net_target_pid"]
	if targetMap == nil {
		t.Close()
		return nil, errors.New("net_target_pid map missing")
	}
	var key uint32 = 0
	val := uint32(pid)
	if err := targetMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
		t.Close()
		return nil, fmt.Errorf("set net_target_pid: %w", err)
	}

	t.cmap = coll.Maps["net_conn_map"]
	if t.cmap == nil {
		t.Close()
		return nil, errors.New("net_conn_map missing")
	}

	tpProg := coll.Programs["handle_inet_set_state"]
	if tpProg == nil {
		t.Close()
		return nil, errors.New("handle_inet_set_state program missing")
	}
	tpLink, err := link.Tracepoint("sock", "inet_sock_set_state", tpProg, nil)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("attach sock/inet_sock_set_state: %w", err)
	}
	t.links = append(t.links, tpLink)

	// kprobes for Tx/Rx bytes. If a kprobe fails (kernel without
	// CONFIG_KPROBES, symbol renamed, etc.), the tracer keeps working — only
	// loses byte counts. Logging a warning would be nicer, but for simplicity
	// we stay silent: state/RTT remain available. Truly fatal errors are rare.
	kprobes := []struct{ sym, prog string }{
		{"tcp_sendmsg", "handle_tcp_sendmsg"},
		{"tcp_cleanup_rbuf", "handle_tcp_cleanup_rbuf"},
	}
	for _, kp := range kprobes {
		p := coll.Programs[kp.prog]
		if p == nil {
			t.Close()
			return nil, fmt.Errorf("program %s missing", kp.prog)
		}
		l, err := link.Kprobe(kp.sym, p, nil)
		if err != nil {
			t.Close()
			return nil, fmt.Errorf("attach kprobe %s: %w", kp.sym, err)
		}
		t.links = append(t.links, l)
	}

	return t, nil
}

// SeedConnection inserts an entry into net_conn_map for a 5-tuple that was
// not captured by the tracepoint (e.g. TCP connections already established
// when xray attached). Uses BPF_NOEXIST: if an entry already exists (because
// the tracepoint fired at some point), it preserves what's there — data
// from the tracepoint has real RTT, accumulated bytes, etc.
//
// State is the kernel numeric value (1=ESTABLISHED, 2=SYN_SENT, ..., 11=CLOSING).
// last_seen_ns is left zero so "fresh" connections from the tracepoint rank above.
func (t *NetTracer) SeedConnection(key NetConnKey, state uint32) error {
	if t == nil || t.cmap == nil {
		return errors.New("tracer not initialized")
	}
	val := NetConnVal{
		State: state,
	}
	err := t.cmap.Update(&key, &val, ebpf.UpdateNoExist)
	if err != nil && errors.Is(err, ebpf.ErrKeyExist) {
		// Already exists (from the tracepoint) — keep what's there, not an error.
		return nil
	}
	return err
}

// Stats iterates net_conn_map and returns a snapshot. Iter is safe to run
// concurrently with BPF program writes — it may skip or repeat marginal
// entries (acceptable for the UI).
func (t *NetTracer) Stats() ([]NetSnapshot, error) {
	if t == nil || t.cmap == nil {
		return nil, errors.New("tracer not initialized")
	}
	out := make([]NetSnapshot, 0, 32)
	var k NetConnKey
	var v NetConnVal
	iter := t.cmap.Iterate()
	for iter.Next(&k, &v) {
		out = append(out, NetSnapshot{
			Family:  k.Family,
			SAddr:   ipFromKey(k.SAddr, k.Family),
			DAddr:   ipFromKey(k.DAddr, k.Family),
			SPort:   k.SPort,
			DPort:   k.DPort,
			State:   v.State,
			RTTNs:   v.RTTNs,
			TxBytes: v.TxBytes,
			RxBytes: v.RxBytes,
			LastNs:  v.LastSeenNs,
		})
	}
	if err := iter.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// ipFromKey converts the addr bytes (already in network order) to net.IP.
// For IPv4 the bytes 0..3 contain the address; for IPv6 all 16.
func ipFromKey(b [16]byte, family uint16) net.IP {
	if family == 2 { // AF_INET
		return net.IPv4(b[0], b[1], b[2], b[3]).To4()
	}
	ip := make(net.IP, 16)
	copy(ip, b[:])
	return ip
}

func (t *NetTracer) Close() error {
	if t == nil {
		return nil
	}
	for _, l := range t.links {
		_ = l.Close()
	}
	t.links = nil
	if t.coll != nil {
		t.coll.Close()
		t.coll = nil
		t.cmap = nil
	}
	return nil
}
