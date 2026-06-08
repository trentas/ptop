package collector

import (
	"bytes"
	"fmt"
	"time"
)

// Filesystem op codes — must match FS_OP_* in internal/bpf/programs/io.bpf.c and
// the FSOp* constants in internal/bpf/io.go. Duplicated here (rather than
// imported from internal/bpf) so this decode logic compiles and is unit-tested
// on any OS, not only the linux+ebpf lane — the same split network_error.go uses.
const (
	fsOpOpenDenied uint32 = 0
	fsOpUnlink     uint32 = 1
	fsOpRename     uint32 = 2
)

// fsOpName maps the kernel op code to the public FSEvent.Op verb.
func fsOpName(op uint32) string {
	switch op {
	case fsOpOpenDenied:
		return "denied"
	case fsOpUnlink:
		return "deleted"
	case fsOpRename:
		return "renamed"
	default:
		return "?"
	}
}

// errnoName maps a positive errno to its symbolic name. Covers the errors that
// actually show up on the open/unlink/rename paths; anything else falls back to
// a numeric form so the value is never lost.
func errnoName(errno int32) string {
	switch errno {
	case 0:
		return ""
	case 1:
		return "EPERM"
	case 2:
		return "ENOENT"
	case 13:
		return "EACCES"
	case 16:
		return "EBUSY"
	case 17:
		return "EEXIST"
	case 18:
		return "EXDEV"
	case 20:
		return "ENOTDIR"
	case 21:
		return "EISDIR"
	case 30:
		return "EROFS"
	case 36:
		return "ENAMETOOLONG"
	case 39:
		return "ENOTEMPTY"
	case 40:
		return "ELOOP"
	default:
		return fmt.Sprintf("errno %d", errno)
	}
}

// cstr decodes a NUL-terminated C string from a fixed kernel buffer, trimming at
// the first NUL (or the whole buffer if unterminated).
func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// decodeFSEvent builds an FSEvent from the raw fields of a fs_event record. ts
// is the wall-clock capture time (stamped by the collector when the event is
// drained — the kernel ts_ns is monotonic, not wall-clock). ret is the syscall
// return: >=0 on success (Errno 0), negative errno on failure.
func decodeFSEvent(ts time.Time, op uint32, ret int32, path, newpath []byte) FSEvent {
	var errno int32
	if ret < 0 {
		errno = -ret
	}
	return FSEvent{
		Timestamp: ts,
		Op:        fsOpName(op),
		Path:      cstr(path),
		NewPath:   cstr(newpath),
		Errno:     errno,
		Err:       errnoName(errno),
	}
}
