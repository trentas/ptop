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

// SocketInfo describes a socket resolved from /proc/net/*.
// Family: "TCP", "UDP", "UNIX". Remote: "10.0.1.5:5432" for inet,
// "/var/run/docker.sock" for unix.
//
// The Raw* fields are only populated for TCP/UDP (not UNIX) and exist to
// allow seeding eBPF maps that use the 5-tuple as key — see
// NetTracer.SeedConnection. Addresses are in network byte order
// (saddr[0] is the high byte) and ports in host order, matching the
// layout the sock:inet_sock_set_state tracepoint produces.
type SocketInfo struct {
	Family string
	Remote string
	State  string // "ESTABLISHED" | "LISTEN" | ... | "" for UNIX

	SAddr    [16]byte // 4 valid bytes for IPv4, rest zero
	DAddr    [16]byte
	SPort    uint16
	DPort    uint16
	AF       uint16 // 2 = AF_INET, 10 = AF_INET6
	StateNum uint32 // raw kernel state (1=ESTABLISHED, 2=SYN_SENT, ...)
}

// SocketResolver maintains an inode→SocketInfo map populated from the
// /proc/net/* files. Calls to Resolve with a stale cache trigger a refresh.
//
// Not exposed as a collector — used inside the FDCollector. Cache TTL: 2s.
// Under high connection churn "(socket:[N])" may show up instead of TCP
// IP:port for the first 1-2 polls.
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

// Resolve returns the SocketInfo for the inode, refreshing the cache if stale.
// If the inode isn't in the map, returns SocketInfo{} and ok=false.
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
// Format (header + 1 connection per line):
//   sl  local_address       rem_address         st  ...  inode  ...
//   0:  0100007F:1F90       00000000:0000       0A  ...  12345  ...
//
// Address: hex IP in little-endian (IPv4) or 4×u32 little-endian (IPv6),
// followed by `:` and port in hex.

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
		if i == 0 || line == "" { // skip header
			continue
		}
		fields := strings.Fields(line)
		// Minimum: sl local rem st tx:rx tr:retr uid timeout inode
		if len(fields) < 10 {
			continue
		}
		// fields[0] = "0:" — ignored
		localAddr := fields[1]
		remAddr := fields[2]
		stHex := strings.ToUpper(fields[3])
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		// Skip sockets without inode (intermediate kernel states)
		if inode == 0 {
			continue
		}

		state := tcpStates[stHex]
		if family == "UDP" {
			state = "" // UDP has no TCP state — leave blank
		}

		// Remote prioritized; LISTEN has no valid remote, so we show the
		// local with a "*:" prefix to signal bind.
		var remote string
		switch {
		case stHex == "0A": // LISTEN
			remote = "*:" + parsePort(localAddr) + " (listen)"
		default:
			remote = parseInetAddr(remAddr, ipv4)
			if remote == "0.0.0.0:0" || remote == "[::]:0" {
				// No peer yet; show local
				remote = parseInetAddr(localAddr, ipv4)
			}
		}

		// Populate raw fields (inet only — UNIX has no 5-tuple).
		stateNum, _ := strconv.ParseUint(stHex, 16, 32)
		af := uint16(2) // AF_INET
		if !ipv4 {
			af = 10 // AF_INET6
		}
		var saddrBytes, daddrBytes [16]byte
		var sport, dport uint16
		fillRawAddr(&saddrBytes, &sport, localAddr, ipv4)
		fillRawAddr(&daddrBytes, &dport, remAddr, ipv4)

		out[inode] = SocketInfo{
			Family:   family,
			Remote:   remote,
			State:    state,
			SAddr:    saddrBytes,
			DAddr:    daddrBytes,
			SPort:    sport,
			DPort:    dport,
			AF:       af,
			StateNum: uint32(stateNum),
		}
	}
}

// fillRawAddr converts "0100007F:1F90" into bytes (network order) + port
// (host order), populating the raw fields of SocketInfo.
//
// Kernel prints each 4-byte chunk of the address as the uint32 in host order
// (printf("%08X", *(u32 *)addr)), so the hex "0100007F" is the uint32
// 0x0100007F which in little-endian memory is [7F,00,00,01] — which
// happens to coincide with the network-order bytes of address 127.0.0.1.
// That's why we byteswap each 4-byte group to recover network order.
func fillRawAddr(dst *[16]byte, port *uint16, hexAddr string, ipv4 bool) {
	colon := strings.LastIndexByte(hexAddr, ':')
	if colon < 0 {
		return
	}
	addrPart := hexAddr[:colon]
	portPart := hexAddr[colon+1:]

	if p, err := strconv.ParseUint(portPart, 16, 16); err == nil {
		*port = uint16(p)
	}

	if ipv4 {
		if len(addrPart) != 8 {
			return
		}
		raw, err := hex.DecodeString(addrPart)
		if err != nil || len(raw) != 4 {
			return
		}
		// Byteswap: hex MSB-first → memory bytes in the reverse order
		// of what printf printed, which gives network order.
		dst[0] = raw[3]
		dst[1] = raw[2]
		dst[2] = raw[1]
		dst[3] = raw[0]
		return
	}
	// IPv6: 4 groups of u32; same per-group byteswap.
	if len(addrPart) != 32 {
		return
	}
	raw, err := hex.DecodeString(addrPart)
	if err != nil || len(raw) != 16 {
		return
	}
	for i := 0; i < 4; i++ {
		dst[i*4+0] = raw[i*4+3]
		dst[i*4+1] = raw[i*4+2]
		dst[i*4+2] = raw[i*4+1]
		dst[i*4+3] = raw[i*4+0]
	}
}

// parseInetAddr converts "0100007F:1F90" → "127.0.0.1:8080" (ipv4)
// or a 32-char hex address + ":" + port for ipv6.
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

// parseIPv4Hex: 0100007F → 127.0.0.1 (kernel writes in little-endian byte order)
func parseIPv4Hex(s string) string {
	if len(s) != 8 {
		return s
	}
	bytes, err := hex.DecodeString(s)
	if err != nil || len(bytes) != 4 {
		return s
	}
	// invert byte order
	return fmt.Sprintf("%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0])
}

// parseIPv6Hex: 4×u32 little-endian in sequence → canonical IPv6
func parseIPv6Hex(s string) string {
	if len(s) != 32 {
		return s
	}
	bytes, err := hex.DecodeString(s)
	if err != nil || len(bytes) != 16 {
		return s
	}
	// Reverse each group of 4 bytes into big-endian
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
// Format:
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
		// May have 7 (no path) or 8 (with path) fields
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

// ─── helper exposed to FDCollector ───────────────────────────────────────────

// extractSocketInode extracts the inode from a "socket:[12345]" link.
// Returns 0 and false if the format doesn't match.
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
