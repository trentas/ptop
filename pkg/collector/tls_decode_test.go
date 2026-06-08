package collector

import (
	"bytes"
	"testing"
	"time"
)

func TestTLSDir(t *testing.T) {
	cases := map[uint32]string{
		tlsDirWrite: "write",
		tlsDirRead:  "read",
		9:           "?",
	}
	for code, want := range cases {
		if got := tlsDir(code); got != want {
			t.Errorf("tlsDir(%d) = %q, want %q", code, got, want)
		}
	}
}

func TestDecodeTLS(t *testing.T) {
	ts := time.Unix(1700000000, 0)
	data := make([]byte, 4096)
	copy(data, "GET / HTTP/1.0\r\n")

	t.Run("write copies exactly captured bytes", func(t *testing.T) {
		p := decodeTLS(ts, tlsDirWrite, 7, 16, 16, data)
		if p.Dir != "write" || p.FD != 7 || p.Len != 16 {
			t.Errorf("unexpected: %+v", p)
		}
		if !bytes.Equal(p.Data, []byte("GET / HTTP/1.0\r\n")) {
			t.Errorf("Data = %q", p.Data)
		}
		if !p.Timestamp.Equal(ts) {
			t.Errorf("Timestamp = %v", p.Timestamp)
		}
	})

	t.Run("metadata only → nil Data", func(t *testing.T) {
		p := decodeTLS(ts, tlsDirRead, -1, 512, 0, data)
		if p.Dir != "read" || p.FD != -1 || p.Len != 512 {
			t.Errorf("unexpected: %+v", p)
		}
		if p.Data != nil {
			t.Errorf("Data = %v, want nil (metadata-only)", p.Data)
		}
	})

	t.Run("captured clamped to buffer length", func(t *testing.T) {
		p := decodeTLS(ts, tlsDirWrite, 3, 9000, 99999, data)
		if len(p.Data) != len(data) {
			t.Errorf("len(Data) = %d, want %d (clamped)", len(p.Data), len(data))
		}
	})
}
