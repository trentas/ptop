package collector

import (
	"testing"
	"time"
)

func TestSignalName(t *testing.T) {
	cases := map[int32]string{
		1:  "SIGHUP",
		9:  "SIGKILL",
		11: "SIGSEGV",
		13: "SIGPIPE",
		15: "SIGTERM",
		34: "SIGRTMIN+0",
		40: "SIGRTMIN+6",
		// Out of the known + RT bands → numeric fallback (never lost).
		99: "SIG99",
	}
	for signo, want := range cases {
		if got := signalName(signo); got != want {
			t.Errorf("signalName(%d) = %q, want %q", signo, got, want)
		}
	}
}

func TestDecodeSignal(t *testing.T) {
	ts := time.Unix(1700000000, 0)
	comm := make([]byte, 16)
	copy(comm, "bash")

	se := decodeSignal(ts, 13, 4242, 99, 0, 1, comm)
	if se.Signal != "SIGPIPE" || se.Signo != 13 {
		t.Errorf("Signal/Signo = %q/%d, want SIGPIPE/13", se.Signal, se.Signo)
	}
	if se.SenderPID != 4242 {
		t.Errorf("SenderPID = %d, want 4242", se.SenderPID)
	}
	if se.SenderComm != "bash" {
		t.Errorf("SenderComm = %q, want bash", se.SenderComm)
	}
	if se.TargetTID != 99 {
		t.Errorf("TargetTID = %d, want 99", se.TargetTID)
	}
	if se.Code != 0 || se.Result != 1 {
		t.Errorf("Code/Result = %d/%d, want 0/1", se.Code, se.Result)
	}
	if !se.Timestamp.Equal(ts) {
		t.Errorf("Timestamp = %v, want %v", se.Timestamp, ts)
	}
}
