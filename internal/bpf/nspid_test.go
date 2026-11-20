package bpf

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseNSpid(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []int
	}{
		{"same namespace", "Name:\tsh\nTgid:\t311035\nNSpid:\t311035\n", []int{311035}},
		{"one level down", "Name:\tsh\nNSpid:\t311067\t1\nNSsid:\t1\n", []int{311067, 1}},
		{"two levels down", "NSpid:\t9001\t812\t7\n", []int{9001, 812, 7}},
		{"no NSpid line (kernel < 4.1)", "Name:\tsh\nPid:\t42\n", nil},
		{"empty NSpid", "NSpid:\t\n", nil},
		{"garbled", "NSpid:\t311067\tx\n", nil},
		{"zero is not a pid", "NSpid:\t0\n", nil},
	}
	for _, c := range cases {
		if got := parseNSpid([]byte(c.in)); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: parseNSpid = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestNSpidChainUnreadable(t *testing.T) {
	if got := NSpidChain(filepath.Join(t.TempDir(), "missing")); got != nil {
		t.Errorf("NSpidChain(missing file) = %v, want nil", got)
	}
}

// This process lives in the namespace its own /proc belongs to (the test does
// not unshare), so its chain has exactly one entry, and it is getpid().
func TestNSpidChainSelf(t *testing.T) {
	chain := NSpidChain("/proc/self/status")
	if chain == nil {
		t.Skip("no NSpid in /proc/self/status (non-Linux, or a kernel before 4.1)")
	}
	if len(chain) != 1 || chain[0] != os.Getpid() {
		t.Errorf("NSpidChain(self) = %v, want [%d]", chain, os.Getpid())
	}
}
