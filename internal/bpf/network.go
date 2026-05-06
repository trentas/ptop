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

// NetConnKey espelha 1:1 a `struct net_key` em programs/network.bpf.c.
// 40 bytes, sem padding além do trailing _pad. cilium/ebpf pode iterar
// HASH map devolvendo essa struct direto se o tamanho bate.
type NetConnKey struct {
	DAddr  [16]byte
	SAddr  [16]byte
	DPort  uint16
	SPort  uint16
	Family uint16
	_      uint16 // pad
}

// NetConnVal espelha `struct net_val`. 48 bytes.
type NetConnVal struct {
	FirstSeenNs   uint64
	LastSeenNs    uint64
	SynSentNs     uint64
	EstablishedNs uint64
	RTTNs         uint64
	State         uint32
	_             uint32 // pad
}

// NetSnapshot é o formato user-friendly devolvido por Stats() — 5-tuple
// já decodificada em net.IP + ports em host order, RTT calculado.
type NetSnapshot struct {
	Family uint16 // 2=IPv4, 10=IPv6
	SAddr  net.IP
	DAddr  net.IP
	SPort  uint16
	DPort  uint16
	State  uint32
	RTTNs  uint64
	LastNs uint64
}

// NetTracer carrega network.bpf.o, attacha o tracepoint
// sock:inet_sock_set_state e expõe Stats() pra ler o map.
type NetTracer struct {
	coll *ebpf.Collection
	link link.Link
	cmap *ebpf.Map
}

func OpenNetTracer(pid int) (*NetTracer, error) {
	if pid <= 0 {
		return nil, errors.New("pid inválido")
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
		return nil, errors.New("net_target_pid map ausente")
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
		return nil, errors.New("net_conn_map ausente")
	}

	prog := coll.Programs["handle_inet_set_state"]
	if prog == nil {
		t.Close()
		return nil, errors.New("program handle_inet_set_state ausente")
	}
	l, err := link.Tracepoint("sock", "inet_sock_set_state", prog, nil)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("attach sock/inet_sock_set_state: %w", err)
	}
	t.link = l

	return t, nil
}

// Stats itera o map net_conn_map e devolve um snapshot. Iter é seguro
// concorrente com escritas do programa BPF — pode pular ou repetir
// entries marginais (aceitável pra UI).
func (t *NetTracer) Stats() ([]NetSnapshot, error) {
	if t == nil || t.cmap == nil {
		return nil, errors.New("tracer não inicializado")
	}
	out := make([]NetSnapshot, 0, 32)
	var k NetConnKey
	var v NetConnVal
	iter := t.cmap.Iterate()
	for iter.Next(&k, &v) {
		out = append(out, NetSnapshot{
			Family: k.Family,
			SAddr:  ipFromKey(k.SAddr, k.Family),
			DAddr:  ipFromKey(k.DAddr, k.Family),
			SPort:  k.SPort,
			DPort:  k.DPort,
			State:  v.State,
			RTTNs:  v.RTTNs,
			LastNs: v.LastSeenNs,
		})
	}
	if err := iter.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// ipFromKey converte os bytes do addr (já em network order) pra net.IP.
// Pra IPv4 os bytes 0..3 contêm o address; pra IPv6 todos os 16.
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
	if t.link != nil {
		_ = t.link.Close()
		t.link = nil
	}
	if t.coll != nil {
		t.coll.Close()
		t.coll = nil
		t.cmap = nil
	}
	return nil
}
