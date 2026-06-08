package collector

import "time"

// TLS payload directions — must match TLS_DIR_* in internal/bpf/programs/tls.bpf.c
// and the TLSDir* constants in internal/bpf/tls.go. Duplicated here (rather than
// imported from internal/bpf) so this decode logic compiles and is unit-tested
// on any OS, not only the linux+ebpf lane — the same split network_error.go uses.
const (
	tlsDirWrite uint32 = 0
	tlsDirRead  uint32 = 1
)

// tlsDir maps the kernel direction code to the public TLSPayload.Dir string.
func tlsDir(dir uint32) string {
	switch dir {
	case tlsDirWrite:
		return "write"
	case tlsDirRead:
		return "read"
	default:
		return "?"
	}
}

// decodeTLS builds a TLSPayload from the raw fields of a tls_event record. ts is
// the wall-clock capture time (stamped by the collector when the event is
// drained — the kernel ts_ns is monotonic). It copies exactly `captured` bytes
// of plaintext from data (defensively bounded by len(data)); Data is nil when
// captured==0 (metadata-only mode).
func decodeTLS(ts time.Time, dir uint32, fd, length int32, captured uint32, data []byte) TLSPayload {
	n := int(captured)
	if n > len(data) {
		n = len(data)
	}
	var payload []byte
	if n > 0 {
		payload = make([]byte, n)
		copy(payload, data[:n])
	}
	return TLSPayload{
		Timestamp: ts,
		Dir:       tlsDir(dir),
		FD:        int(fd),
		Len:       int(length),
		Data:      payload,
	}
}
