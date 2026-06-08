//go:build linux && ebpf

package bpf

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
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
	Retransmits   uint32 // #56 — running tcp_retransmit_skb count
}

// Net error kinds — must match NET_ERR_* in programs/network.bpf.c.
const (
	NetErrRefused    uint32 = 0
	NetErrReset      uint32 = 1
	NetErrRetransmit uint32 = 2
)

// NetErrorRecord is the 1:1 layout of struct net_error_event in
// programs/network.bpf.c. Fixed size 64 bytes; binary.LittleEndian parses it
// directly from the ring buffer. Key is the connection 5-tuple (network-order
// addrs, host-order ports), decoded the same way as net_conn_map keys.
type NetErrorRecord struct {
	TsNs        uint64
	Key         NetConnKey // 40 bytes
	Kind        uint32
	Retransmits uint32
	DetailNs    uint64
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
	rb    *ringbuf.Reader // #56 — net_error_events channel
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
	tf, err := resolveTarget(pid)
	if err != nil {
		t.Close()
		return nil, err
	}
	if err := writeTargetFilter(targetMap, tf); err != nil {
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

	// Net error probes (#56). Non-fatal — unlike the byte kprobes above, a
	// kernel without these symbols (renamed, or CONFIG_KPROBES off) simply
	// yields no net-error events; connection tracking is unaffected, so we log
	// and continue rather than failing the whole tracer.
	errKprobes := []struct{ sym, prog string }{
		{"tcp_reset", "handle_tcp_reset"},
		{"tcp_retransmit_skb", "handle_tcp_retransmit"},
	}
	for _, kp := range errKprobes {
		p := coll.Programs[kp.prog]
		if p == nil {
			fmt.Fprintf(os.Stderr, "network: program %s missing; net errors degraded\n", kp.prog)
			continue
		}
		l, err := link.Kprobe(kp.sym, p, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "network: attach kprobe %s failed (%v); net errors degraded\n", kp.sym, err)
			continue
		}
		t.links = append(t.links, l)
	}

	// Open the net-error ring buffer. This map is part of our own program, so
	// a miss here means a corrupt object — fatal, matching io.go/heap.go.
	errMap := coll.Maps["net_error_events"]
	if errMap == nil {
		t.Close()
		return nil, errors.New("net_error_events ringbuf missing")
	}
	rb, err := ringbuf.NewReader(errMap)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("net error ringbuf reader: %w", err)
	}
	t.rb = rb

	return t, nil
}

// NextError blocks until the next net-error event arrives from the kernel.
// Returns io.EOF once the tracer is closed. A short/garbled record is reported
// as an error but does not close the stream — the caller keeps reading.
func (t *NetTracer) NextError() (NetErrorRecord, error) {
	var rec NetErrorRecord
	if t == nil || t.rb == nil {
		return rec, errors.New("tracer not initialized")
	}
	r, err := t.rb.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return rec, io.EOF
		}
		return rec, err
	}
	if len(r.RawSample) < 64 {
		return rec, fmt.Errorf("short net error event: %d bytes", len(r.RawSample))
	}
	if err := binary.Read(bytes.NewReader(r.RawSample), binary.LittleEndian, &rec); err != nil {
		return rec, fmt.Errorf("decode net error: %w", err)
	}
	return rec, nil
}

// SeedConnection inserts an entry into net_conn_map for a 5-tuple that was
// not captured by the tracepoint (e.g. TCP connections already established
// when ptop attached). Uses BPF_NOEXIST: if an entry already exists (because
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
	// Close the reader first so a blocked NextError unblocks with io.EOF.
	if t.rb != nil {
		_ = t.rb.Close()
		t.rb = nil
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
