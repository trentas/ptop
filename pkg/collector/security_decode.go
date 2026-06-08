package collector

import (
	"fmt"
	"strings"
	"time"
)

// Decoder for the security collector (#59). Build-tag-free so it compiles and is
// unit-tested on any OS (the fs_decode.go / signal_decode.go idiom). Constants
// mirror programs/security.bpf.c.
const (
	secKindExecMap = 0
	secKindLSM     = 1

	secOpMmap     = 0
	secOpMprotect = 1

	protRead  = 0x1
	protWrite = 0x2
	protExec  = 0x4

	mapAnonymous = 0x20
)

// protString renders a PROT_* bitmask as rwx, with '-' for absent bits.
func protString(prot uint32) string {
	b := []byte("---")
	if prot&protRead != 0 {
		b[0] = 'r'
	}
	if prot&protWrite != 0 {
		b[1] = 'w'
	}
	if prot&protExec != 0 {
		b[2] = 'x'
	}
	return string(b)
}

// decodeSecurityExecMap builds the structural part of an exec-map SecurityEvent
// (the symbolized call site is filled in by the collector). ts is the wall-clock
// capture time (the kernel ts_ns is monotonic, not wall-clock).
func decodeSecurityExecMap(ts time.Time, op, prot, flags uint32, addr, length uint64) SecurityEvent {
	e := SecurityEvent{
		Timestamp: ts,
		Kind:      "exec-map",
		Addr:      addr,
		Len:       length,
		Prot:      prot,
		WriteExec: prot&protWrite != 0, // exec-map is only emitted with PROT_EXEC set
		Anon:      flags&mapAnonymous != 0,
	}
	switch op {
	case secOpMmap:
		e.Op = "mmap"
	case secOpMprotect:
		e.Op = "mprotect"
	default:
		e.Op = fmt.Sprintf("op%d", op)
	}
	return e
}

// decodeSecurityLSM builds an lsm-decision SecurityEvent from the SELinux AVC
// perm masks. Perm-name and class/context decoding are deferred (need the SELinux
// per-class tables), so the detail reports the raw masks — enough to flag that a
// denial occurred and which permission bits.
func decodeSecurityLSM(ts time.Time, requested, denied, audited uint32) SecurityEvent {
	return SecurityEvent{
		Timestamp: ts,
		Kind:      "lsm-decision",
		Detail: fmt.Sprintf("selinux denied=0x%x requested=0x%x audited=0x%x",
			denied, requested, audited),
	}
}

// isLoaderModule reports whether a module basename is the dynamic loader or libc
// — frames to skip when walking a stack toward the application call site that
// triggered the mapping (the leaf is libc's mmap/mprotect wrapper). An empty
// module is NOT a loader: it's an unresolved address, often the JIT/anonymous
// executable region itself, which is exactly what we want to surface.
func isLoaderModule(mod string) bool {
	if i := strings.LastIndexByte(mod, '/'); i >= 0 {
		mod = mod[i+1:]
	}
	for _, p := range []string{"libc", "ld-", "ld.so", "ld-linux", "libpthread", "libdl"} {
		if strings.HasPrefix(mod, p) {
			return true
		}
	}
	return false
}

// securityAddrHex formats a call-site address; 0 means the stack walk failed and
// renders as "unknown" (same convention as heapAddrHex).
func securityAddrHex(addr uint64) string {
	if addr == 0 {
		return "unknown"
	}
	return fmt.Sprintf("0x%x", addr)
}
