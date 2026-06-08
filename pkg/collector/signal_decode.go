package collector

import (
	"fmt"
	"time"
)

// signalNames maps the standard signal numbers (1..31, shared across the arches
// ptop targets) to their symbolic names. Real-time signals and anything else
// fall back to a numeric form so the value is never lost. Kept here (not derived
// from x/sys/unix) so it compiles and is unit-tested on any OS, not only the
// linux+ebpf lane — the same split network_error.go/fs_decode.go use.
var signalNames = map[int32]string{
	1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL", 5: "SIGTRAP",
	6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE", 9: "SIGKILL", 10: "SIGUSR1",
	11: "SIGSEGV", 12: "SIGUSR2", 13: "SIGPIPE", 14: "SIGALRM", 15: "SIGTERM",
	16: "SIGSTKFLT", 17: "SIGCHLD", 18: "SIGCONT", 19: "SIGSTOP", 20: "SIGTSTP",
	21: "SIGTTIN", 22: "SIGTTOU", 23: "SIGURG", 24: "SIGXCPU", 25: "SIGXFSZ",
	26: "SIGVTALRM", 27: "SIGPROF", 28: "SIGWINCH", 29: "SIGIO", 30: "SIGPWR",
	31: "SIGSYS",
}

// signalName renders a signal number as its symbolic name, the real-time band
// as SIGRTMIN+n, and anything else as SIG<n>.
func signalName(signo int32) string {
	if n, ok := signalNames[signo]; ok {
		return n
	}
	if signo >= 34 && signo <= 64 {
		return fmt.Sprintf("SIGRTMIN+%d", signo-34)
	}
	return fmt.Sprintf("SIG%d", signo)
}

// decodeSignal builds a SignalEvent from the raw fields of a sig_event record.
// ts is the wall-clock capture time (stamped by the collector when the event is
// drained — the kernel ts_ns is monotonic, not wall-clock).
func decodeSignal(ts time.Time, signo, senderPID, targetTID, code, result int32, comm []byte) SignalEvent {
	return SignalEvent{
		Timestamp:  ts,
		Signal:     signalName(signo),
		Signo:      signo,
		SenderPID:  senderPID,
		SenderComm: cstr(comm),
		TargetTID:  targetTID,
		Code:       code,
		Result:     result,
	}
}
