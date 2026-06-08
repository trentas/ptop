package collector

import (
	"testing"
	"time"
)

func TestFSOpName(t *testing.T) {
	cases := map[uint32]string{
		fsOpOpenDenied: "denied",
		fsOpUnlink:     "deleted",
		fsOpRename:     "renamed",
		99:             "?",
	}
	for code, want := range cases {
		if got := fsOpName(code); got != want {
			t.Errorf("fsOpName(%d) = %q, want %q", code, got, want)
		}
	}
}

func TestErrnoName(t *testing.T) {
	cases := map[int32]string{
		0:  "",
		1:  "EPERM",
		2:  "ENOENT",
		13: "EACCES",
		39: "ENOTEMPTY",
		// Unknown errno falls back to a numeric form (never lost).
		77: "errno 77",
	}
	for errno, want := range cases {
		if got := errnoName(errno); got != want {
			t.Errorf("errnoName(%d) = %q, want %q", errno, got, want)
		}
	}
}

func TestCstr(t *testing.T) {
	// NUL-terminated: trim at the first NUL.
	buf := make([]byte, 16)
	copy(buf, "/etc/shadow")
	if got := cstr(buf); got != "/etc/shadow" {
		t.Errorf("cstr = %q, want /etc/shadow", got)
	}
	// Unterminated: the whole buffer is the string.
	full := []byte("abcd")
	if got := cstr(full); got != "abcd" {
		t.Errorf("cstr(unterminated) = %q, want abcd", got)
	}
	// Empty (leading NUL) → "".
	if got := cstr(make([]byte, 8)); got != "" {
		t.Errorf("cstr(empty) = %q, want \"\"", got)
	}
}

// pathBuf builds a fixed [256]byte kernel buffer from a string (NUL-padded).
func pathBuf(s string) []byte {
	b := make([]byte, 256)
	copy(b, s)
	return b
}

func TestDecodeFSEvent(t *testing.T) {
	ts := time.Unix(1700000000, 0)

	t.Run("open denial carries errno name", func(t *testing.T) {
		fe := decodeFSEvent(ts, fsOpOpenDenied, -13, pathBuf("/etc/shadow"), pathBuf(""))
		if fe.Op != "denied" {
			t.Errorf("Op = %q, want denied", fe.Op)
		}
		if fe.Path != "/etc/shadow" {
			t.Errorf("Path = %q", fe.Path)
		}
		if fe.Errno != 13 || fe.Err != "EACCES" {
			t.Errorf("Errno/Err = %d/%q, want 13/EACCES", fe.Errno, fe.Err)
		}
		if fe.NewPath != "" {
			t.Errorf("NewPath = %q, want empty", fe.NewPath)
		}
		if !fe.Timestamp.Equal(ts) {
			t.Errorf("Timestamp = %v, want %v", fe.Timestamp, ts)
		}
	})

	t.Run("successful delete has zero errno", func(t *testing.T) {
		fe := decodeFSEvent(ts, fsOpUnlink, 0, pathBuf("/tmp/cache.bin"), pathBuf(""))
		if fe.Op != "deleted" || fe.Path != "/tmp/cache.bin" {
			t.Errorf("unexpected: %+v", fe)
		}
		if fe.Errno != 0 || fe.Err != "" {
			t.Errorf("Errno/Err = %d/%q, want 0/\"\"", fe.Errno, fe.Err)
		}
	})

	t.Run("rename carries both paths", func(t *testing.T) {
		fe := decodeFSEvent(ts, fsOpRename, 0, pathBuf("/data/a.tmp"), pathBuf("/data/a.db"))
		if fe.Op != "renamed" {
			t.Errorf("Op = %q, want renamed", fe.Op)
		}
		if fe.Path != "/data/a.tmp" || fe.NewPath != "/data/a.db" {
			t.Errorf("paths = %q → %q", fe.Path, fe.NewPath)
		}
	})
}
