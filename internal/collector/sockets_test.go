//go:build linux

package collector

import (
	"os"
	"testing"
)

func TestParseIPv4Hex(t *testing.T) {
	cases := map[string]string{
		"0100007F": "127.0.0.1",
		"0101A8C0": "192.168.1.1",
		"00000000": "0.0.0.0",
	}
	for hex, want := range cases {
		if got := parseIPv4Hex(hex); got != want {
			t.Errorf("parseIPv4Hex(%q)=%q, expected %q", hex, got, want)
		}
	}
}

func TestParseIPv6Hex_loopback(t *testing.T) {
	// ::1 in little-endian per 4-byte group
	hex := "00000000000000000000000001000000"
	got := parseIPv6Hex(hex)
	if got != "::1" {
		t.Errorf("parseIPv6Hex(::1)=%q", got)
	}
}

func TestParsePortStr(t *testing.T) {
	cases := map[string]string{
		"1F90": "8080",
		"01BB": "443",
		"0050": "80",
	}
	for hex, want := range cases {
		if got := parsePortStr(hex); got != want {
			t.Errorf("parsePortStr(%q)=%q, expected %q", hex, got, want)
		}
	}
}

func TestExtractSocketInode(t *testing.T) {
	cases := []struct {
		link    string
		want    uint64
		wantOk  bool
	}{
		{"socket:[12345]", 12345, true},
		{"socket:[0]", 0, true},
		{"pipe:[999]", 0, false},
		{"socket:[abc]", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		got, ok := extractSocketInode(c.link)
		if got != c.want || ok != c.wantOk {
			t.Errorf("extractSocketInode(%q)=(%d,%v), expected (%d,%v)",
				c.link, got, ok, c.want, c.wantOk)
		}
	}
}

const sampleProcNetTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 0100007F:E96A 01 00000000:00000000 00:00000000 00000000  1000        0 11111 1 0000000000000000 100 0 0 10 0
   1: 00000000:1F40 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 22222 1 0000000000000000 100 0 0 10 0
`

func TestParseInetFile_tcp(t *testing.T) {
	tmp := t.TempDir() + "/tcp"
	if err := writeFileForTest(tmp, sampleProcNetTCP); err != nil {
		t.Fatal(err)
	}
	out := make(map[uint64]SocketInfo)
	parseInetFile(tmp, "TCP", true, out)

	if len(out) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(out))
	}
	if est := out[11111]; est.Family != "TCP" || est.State != "ESTABLISHED" {
		t.Errorf("inode 11111 expected ESTABLISHED TCP, got %+v", est)
	}
	if est := out[11111]; est.Remote != "127.0.0.1:59754" {
		t.Errorf("remote inode 11111: got %q", est.Remote)
	}
	if lst := out[22222]; lst.State != "LISTEN" {
		t.Errorf("inode 22222 expected LISTEN, got %+v", lst)
	}
	if !contains(out[22222].Remote, "8000") {
		t.Errorf("LISTEN must show local port 8000, got %q", out[22222].Remote)
	}
}

const sampleProcNetUnix = `Num       RefCount Protocol Flags    Type St Inode Path
00000000: 00000002 00000000 00010000 0001 01 33333 /var/run/docker.sock
00000000: 00000002 00000000 00010000 0001 01 44444
`

func TestParseUnixFile(t *testing.T) {
	tmp := t.TempDir() + "/unix"
	if err := writeFileForTest(tmp, sampleProcNetUnix); err != nil {
		t.Fatal(err)
	}
	out := make(map[uint64]SocketInfo)
	parseUnixFile(tmp, out)

	if len(out) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(out))
	}
	if got := out[33333]; got.Family != "UNIX" || got.Remote != "/var/run/docker.sock" {
		t.Errorf("inode 33333: %+v", got)
	}
	if got := out[44444]; got.Remote != "(anon)" {
		t.Errorf("anon inode: expected (anon), got %q", got.Remote)
	}
}

func TestFillRawAddr_ipv4(t *testing.T) {
	var addr [16]byte
	var port uint16
	fillRawAddr(&addr, &port, "0100007F:1F90", true)
	// 127.0.0.1 in network order: [7F, 00, 00, 01]
	want := [4]byte{0x7F, 0x00, 0x00, 0x01}
	if [4]byte(addr[:4]) != want {
		t.Errorf("saddr expected %v, got %v", want, addr[:4])
	}
	if port != 8080 {
		t.Errorf("port expected 8080, got %d", port)
	}
	// Rest must stay zero
	for i := 4; i < 16; i++ {
		if addr[i] != 0 {
			t.Errorf("addr[%d] expected 0, got %d", i, addr[i])
		}
	}
}

func TestParseInetFile_rawFields(t *testing.T) {
	tmp := t.TempDir() + "/tcp"
	if err := writeFileForTest(tmp, sampleProcNetTCP); err != nil {
		t.Fatal(err)
	}
	out := make(map[uint64]SocketInfo)
	parseInetFile(tmp, "TCP", true, out)

	est := out[11111]
	// 127.0.0.1:E96A → DAddr [7F,00,00,01], DPort 0xE96A=59754
	wantDAddr := [4]byte{0x7F, 0x00, 0x00, 0x01}
	if [4]byte(est.DAddr[:4]) != wantDAddr {
		t.Errorf("DAddr expected %v, got %v", wantDAddr, est.DAddr[:4])
	}
	if est.DPort != 59754 {
		t.Errorf("DPort expected 59754, got %d", est.DPort)
	}
	if est.AF != 2 {
		t.Errorf("AF expected 2 (AF_INET), got %d", est.AF)
	}
	if est.StateNum != 1 {
		t.Errorf("StateNum expected 1 (ESTABLISHED), got %d", est.StateNum)
	}
}

// helpers

func writeFileForTest(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
