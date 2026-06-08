package collector

import (
	"fmt"
	"net"
	"time"
)

// Net error kind codes — must match NET_ERR_* in network.bpf.c and the
// NetErr* constants in internal/bpf/network.go. Duplicated here (rather than
// imported from internal/bpf) so this decode logic compiles and is unit-tested
// on any OS, not only the linux+ebpf lane — the same split heap_agg.go uses.
const (
	netErrKindRefused    uint32 = 0
	netErrKindReset      uint32 = 1
	netErrKindRetransmit uint32 = 2
)

// netErrKind maps the kernel kind code to the public NetError.Kind string.
func netErrKind(kind uint32) string {
	switch kind {
	case netErrKindRefused:
		return "refused"
	case netErrKindReset:
		return "reset"
	case netErrKindRetransmit:
		return "retransmit"
	default:
		return "?"
	}
}

// formatRemote renders "host:port" (IPv4) or "[host]:port" (IPv6) from raw
// network-order address bytes, a host-order port, and the address family
// (2=AF_INET, 10=AF_INET6). Mirrors ipFromKey+formatNetAddr in the ebpf-tagged
// loader/collector, kept here so it stays testable off-Linux.
func formatRemote(addr [16]byte, port uint16, family uint16) string {
	if family == 2 { // AF_INET
		ip := net.IPv4(addr[0], addr[1], addr[2], addr[3]).To4()
		return fmt.Sprintf("%s:%d", ip.String(), port)
	}
	ip := make(net.IP, 16)
	copy(ip, addr[:])
	return fmt.Sprintf("[%s]:%d", ip.String(), port)
}

// decodeNetError builds a NetError from the raw fields of a net_error_event
// record. ts is the wall-clock capture time (stamped by the collector when the
// event is drained — the kernel ts_ns is monotonic, not wall-clock). daddr/
// dport/family identify the peer; detailNs is converted to milliseconds.
func decodeNetError(ts time.Time, daddr [16]byte, dport, family uint16, kind, retransmits uint32, detailNs uint64) NetError {
	return NetError{
		Timestamp:   ts,
		Kind:        netErrKind(kind),
		Remote:      formatRemote(daddr, dport, family),
		Retransmits: retransmits,
		DetailMs:    float64(detailNs) / 1e6,
	}
}
