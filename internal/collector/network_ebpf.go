//go:build linux && ebpf

package collector

import (
	"fmt"
	"sort"
	"time"

	"github.com/trentas/xray/internal/bpf"
)

// NetworkEBPFCollector usa o tracepoint sock:inet_sock_set_state pra
// descobrir conexões TCP do PID alvo em tempo real, e publica []NetConn
// a cada 500ms. Latência vem do RTT do handshake (SYN_SENT → ESTABLISHED).
//
// Bytes Tx/Rx ficam zerados nesta primeira fase — adicionar exigiria
// kprobes em tcp_sendmsg/tcp_cleanup_rbuf com leitura de struct sock,
// que requer vmlinux.h ou offsets manuais (seguir em issue separado).
type NetworkEBPFCollector struct {
	tracer *bpf.NetTracer
	ch     chan interface{}
	stop   chan struct{}
}

func NewNetworkEBPFCollector() *NetworkEBPFCollector {
	return &NetworkEBPFCollector{
		ch:   make(chan interface{}, 4),
		stop: make(chan struct{}),
	}
}

func (c *NetworkEBPFCollector) Start(pid int) error {
	tracer, err := bpf.OpenNetTracer(pid)
	if err != nil {
		return fmt.Errorf("network eBPF: %w", err)
	}
	c.tracer = tracer
	go c.publishLoop()
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
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
			conns := c.snapshot()
			select {
			case c.ch <- conns:
			default:
			}
		}
	}
}

// snapshot lê o map e converte cada entry em NetConn. Filtra estados
// CLOSE (7) — conexões fechadas não interessam pra view "Active
// Connections". Ordena por mais recente atividade primeiro.
func (c *NetworkEBPFCollector) snapshot() []NetConn {
	if c.tracer == nil {
		return nil
	}
	snaps, err := c.tracer.Stats()
	if err != nil {
		return nil
	}
	out := make([]NetConn, 0, len(snaps))
	for _, s := range snaps {
		if s.State == tcpStateCLOSE {
			continue
		}
		latMs := float64(s.RTTNs) / 1e6
		out = append(out, NetConn{
			Type:      "TCP",
			Remote:    formatNetAddr(s.DAddr.String(), s.DPort, s.Family),
			State:     mapTCPState(s.State),
			Dir:       "→",
			LatencyMs: latMs,
		})
	}
	// Ordem estável: mais recente primeiro pra não pular linhas no terminal.
	sort.SliceStable(out, func(i, j int) bool {
		return snaps[i].LastNs > snaps[j].LastNs
	})
	return out
}

// TCP states do kernel (linux/tcp.h) — também usado em sockets.go pro
// /proc/net/tcp parser, mas lá os valores vêm em hex string.
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

func formatNetAddr(ip string, port uint16, family uint16) string {
	if family == 10 { // AF_INET6
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}
