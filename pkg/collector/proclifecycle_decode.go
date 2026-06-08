package collector

import (
	"fmt"
	"time"
)

// Decoder for the exec-lineage collector (#60). Build-tag-free so it compiles
// and is unit-tested on any OS (the fs_decode.go / signal_decode.go idiom). The
// kind constants mirror PROC_FORK/PROC_EXEC/PROC_EXIT in programs/proc.bpf.c.
const (
	procKindFork = 0
	procKindExec = 1
	procKindExit = 2
)

// procKindName maps a raw kind to its symbolic verb, falling back to a numeric
// form so an unexpected value is never silently lost.
func procKindName(kind uint32) string {
	switch kind {
	case procKindFork:
		return "fork"
	case procKindExec:
		return "exec"
	case procKindExit:
		return "exit"
	default:
		return fmt.Sprintf("kind%d", kind)
	}
}

// decodeProcLifecycle builds a ProcLifecycleEvent from the raw fields of a
// proc_event record. ts is the wall-clock capture time (stamped by the collector
// when the event is drained — the kernel ts_ns is monotonic, not wall-clock).
// filename is only meaningful for exec; it is cleared for other kinds so a
// stale buffer can't leak into fork/exit events.
func decodeProcLifecycle(ts time.Time, kind uint32, pid, ppid int32, comm, filename []byte) ProcLifecycleEvent {
	e := ProcLifecycleEvent{
		Timestamp: ts,
		Kind:      procKindName(kind),
		PID:       pid,
		PPID:      ppid,
		Comm:      cstr(comm),
	}
	if kind == procKindExec {
		e.Filename = cstr(filename)
	}
	return e
}
