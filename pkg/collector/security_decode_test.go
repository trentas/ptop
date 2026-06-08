package collector

import (
	"testing"
	"time"
)

func TestProtString(t *testing.T) {
	cases := map[uint32]string{
		0:                               "---",
		protRead:                        "r--",
		protRead | protExec:             "r-x",
		protWrite | protExec:            "-wx",
		protRead | protWrite | protExec: "rwx",
		protExec:                        "--x",
	}
	for prot, want := range cases {
		if got := protString(prot); got != want {
			t.Errorf("protString(0x%x) = %q, want %q", prot, got, want)
		}
	}
}

func TestDecodeSecurityExecMap(t *testing.T) {
	ts := time.Now()

	// mmap RWX anonymous — the high-signal injection shape.
	e := decodeSecurityExecMap(ts, secOpMmap, protRead|protWrite|protExec, mapAnonymous, 0x7f00, 4096)
	if e.Kind != "exec-map" || e.Op != "mmap" {
		t.Errorf("kind/op = %q/%q", e.Kind, e.Op)
	}
	if !e.WriteExec {
		t.Error("WriteExec should be true for RWX")
	}
	if !e.Anon {
		t.Error("Anon should be true for MAP_ANONYMOUS")
	}
	if e.Addr != 0x7f00 || e.Len != 4096 {
		t.Errorf("addr/len = 0x%x/%d", e.Addr, e.Len)
	}

	// mprotect r-x (the JIT finalize step): exec, not writable, flags=0 → not anon.
	e = decodeSecurityExecMap(ts, secOpMprotect, protRead|protExec, 0, 0x8000, 8192)
	if e.Op != "mprotect" {
		t.Errorf("op = %q, want mprotect", e.Op)
	}
	if e.WriteExec {
		t.Error("WriteExec should be false for r-x")
	}
	if e.Anon {
		t.Error("Anon should be false when flags=0 (mprotect)")
	}
}

func TestDecodeSecurityLSM(t *testing.T) {
	e := decodeSecurityLSM(time.Now(), 0x2, 0x8, 0x8)
	if e.Kind != "lsm-decision" {
		t.Errorf("kind = %q", e.Kind)
	}
	if e.Detail != "selinux denied=0x8 requested=0x2 audited=0x8" {
		t.Errorf("detail = %q", e.Detail)
	}
}

func TestSecurityAddrHex(t *testing.T) {
	if got := securityAddrHex(0); got != "unknown" {
		t.Errorf("securityAddrHex(0) = %q, want unknown", got)
	}
	if got := securityAddrHex(0x55e3f2a1b4c0); got != "0x55e3f2a1b4c0" {
		t.Errorf("securityAddrHex = %q", got)
	}
}
