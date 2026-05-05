package collector

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SocketInfo descreve um socket resolvido a partir de /proc/net/*.
// Family: "TCP", "UDP", "UNIX". Remote: "10.0.1.5:5432" para inet,
// "/var/run/docker.sock" para unix.
type SocketInfo struct {
	Family string
	Remote string
	State  string // "ESTABLISHED" | "LISTEN" | ... | "" para UNIX
}

// SocketResolver mantém um map inode→SocketInfo populado dos arquivos
// /proc/net/*. Chamadas a Resolve com cache stale acionam refresh.
//
// Não é exposto como collector — é usado dentro do FDCollector.
// Cache TTL: 2s. Sob alta rotatividade de conexões pode aparecer
// "(socket:[N])" no lugar de TCP IP:port nos primeiros 1-2 polls.
type SocketResolver struct {
	mu       sync.Mutex
	cache    map[uint64]SocketInfo
	cachedAt time.Time
	ttl      time.Duration
}

func NewSocketResolver() *SocketResolver {
	return &SocketResolver{
		cache: make(map[uint64]SocketInfo),
		ttl:   2 * time.Second,
	}
}

// Resolve devolve a SocketInfo do inode, atualizando o cache se stale.
// Se o inode não está no map, retorna SocketInfo{} e ok=false.
func (r *SocketResolver) Resolve(inode uint64) (SocketInfo, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if time.Since(r.cachedAt) > r.ttl {
		r.refreshLocked()
		r.cachedAt = time.Now()
	}
	info, ok := r.cache[inode]
	return info, ok
}

func (r *SocketResolver) refreshLocked() {
	r.cache = make(map[uint64]SocketInfo, len(r.cache))
	parseInetFile("/proc/net/tcp", "TCP", true, r.cache)
	parseInetFile("/proc/net/tcp6", "TCP", false, r.cache)
	parseInetFile("/proc/net/udp", "UDP", true, r.cache)
	parseInetFile("/proc/net/udp6", "UDP", false, r.cache)
	parseUnixFile("/proc/net/unix", r.cache)
}

// ─── /proc/net/{tcp,tcp6,udp,udp6} ───────────────────────────────────────────
//
// Formato (header + 1 conexão por linha):
//   sl  local_address       rem_address         st  ...  inode  ...
//   0:  0100007F:1F90       00000000:0000       0A  ...  12345  ...
//
// Address: hex IP em little-endian (IPv4) ou 4×u32 little-endian (IPv6),
// seguido de `:` e porta em hex.

var tcpStates = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

func parseInetFile(path, family string, ipv4 bool, out map[uint64]SocketInfo) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if i == 0 || line == "" { // pula header
			continue
		}
		fields := strings.Fields(line)
		// Mínimo: sl local rem st tx:rx tr:retr uid timeout inode
		if len(fields) < 10 {
			continue
		}
		// fields[0] = "0:" — ignorado
		localAddr := fields[1]
		remAddr := fields[2]
		stHex := strings.ToUpper(fields[3])
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		// Pula sockets sem inode (estados intermediários do kernel)
		if inode == 0 {
			continue
		}

		state := tcpStates[stHex]
		if family == "UDP" {
			state = "" // UDP não tem state TCP — deixa em branco
		}

		// Remote priorizado; LISTEN não tem remote válido, então mostramos
		// o local com prefixo "*:" para sinalizar bind.
		var remote string
		switch {
		case stHex == "0A": // LISTEN
			remote = "*:" + parsePort(localAddr) + " (listen)"
		default:
			remote = parseInetAddr(remAddr, ipv4)
			if remote == "0.0.0.0:0" || remote == "[::]:0" {
				// Sem peer ainda; mostra local
				remote = parseInetAddr(localAddr, ipv4)
			}
		}

		out[inode] = SocketInfo{
			Family: family,
			Remote: remote,
			State:  state,
		}
	}
}

// parseInetAddr converte "0100007F:1F90" → "127.0.0.1:8080" (ipv4)
// ou um endereço hexa de 32 chars + ":" + porta para ipv6.
func parseInetAddr(s string, ipv4 bool) string {
	colon := strings.LastIndexByte(s, ':')
	if colon < 0 {
		return s
	}
	addrHex := s[:colon]
	portStr := parsePortStr(s[colon+1:])

	if ipv4 {
		ip := parseIPv4Hex(addrHex)
		return ip + ":" + portStr
	}
	ip := parseIPv6Hex(addrHex)
	return "[" + ip + "]:" + portStr
}

func parsePort(s string) string {
	colon := strings.LastIndexByte(s, ':')
	if colon < 0 {
		return ""
	}
	return parsePortStr(s[colon+1:])
}

func parsePortStr(hexStr string) string {
	port, err := strconv.ParseUint(hexStr, 16, 32)
	if err != nil {
		return "?"
	}
	return strconv.FormatUint(port, 10)
}

// parseIPv4Hex: 0100007F → 127.0.0.1 (kernel escreve em little-endian byte order)
func parseIPv4Hex(s string) string {
	if len(s) != 8 {
		return s
	}
	bytes, err := hex.DecodeString(s)
	if err != nil || len(bytes) != 4 {
		return s
	}
	// inverte byte order
	return fmt.Sprintf("%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0])
}

// parseIPv6Hex: 4×u32 little-endian em sequência → IPv6 canônico
func parseIPv6Hex(s string) string {
	if len(s) != 32 {
		return s
	}
	bytes, err := hex.DecodeString(s)
	if err != nil || len(bytes) != 16 {
		return s
	}
	// Reverte cada grupo de 4 bytes para big-endian
	swapped := make([]byte, 16)
	for i := 0; i < 4; i++ {
		swapped[i*4+0] = bytes[i*4+3]
		swapped[i*4+1] = bytes[i*4+2]
		swapped[i*4+2] = bytes[i*4+1]
		swapped[i*4+3] = bytes[i*4+0]
	}
	return net.IP(swapped).String()
}

// ─── /proc/net/unix ──────────────────────────────────────────────────────────
//
// Formato:
//   Num       RefCount Protocol Flags    Type St Inode Path
//   00000000: 00000002 00000000 00010000 0001 01 12345 /var/run/docker.sock

var unixStates = map[string]string{
	"01": "FREE",
	"02": "UNCONNECTED",
	"03": "CONNECTING",
	"04": "CONNECTED",
	"05": "DISCONNECTING",
}

func parseUnixFile(path string, out map[uint64]SocketInfo) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if i == 0 || line == "" {
			continue
		}
		fields := strings.Fields(line)
		// Pode ter 7 (sem path) ou 8 (com path) campos
		if len(fields) < 7 {
			continue
		}
		inode, err := strconv.ParseUint(fields[6], 10, 64)
		if err != nil || inode == 0 {
			continue
		}
		path := ""
		if len(fields) >= 8 {
			path = strings.Join(fields[7:], " ")
		}
		stHex := strings.ToUpper(fields[5])
		state := unixStates[stHex]

		remote := path
		if remote == "" {
			remote = "(anon)"
		}
		out[inode] = SocketInfo{
			Family: "UNIX",
			Remote: remote,
			State:  state,
		}
	}
}

// ─── helper exposto pro FDCollector ──────────────────────────────────────────

// extractSocketInode extrai o inode de um link "socket:[12345]".
// Retorna 0 e false se o formato não bate.
func extractSocketInode(link string) (uint64, bool) {
	const prefix = "socket:["
	if !strings.HasPrefix(link, prefix) {
		return 0, false
	}
	end := strings.IndexByte(link[len(prefix):], ']')
	if end < 0 {
		return 0, false
	}
	n, err := strconv.ParseUint(link[len(prefix):len(prefix)+end], 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}
