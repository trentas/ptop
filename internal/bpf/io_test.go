//go:build linux && ebpf

package bpf

import (
	"encoding/binary"
	"testing"
)

// decodeIOEvent reads the layout io.bpf.c writes: struct io_event, and for an
// open struct io_open_event, the header followed by the path (#162).
func TestDecodeIOEvent(t *testing.T) {
	le := binary.LittleEndian
	hdr := func(op uint32, dfd int32) []byte {
		b := make([]byte, ioEventSize)
		le.PutUint64(b[0:], 1)   // ts
		le.PutUint64(b[8:], 2)   // lat
		le.PutUint64(b[16:], 3)  // bytes
		le.PutUint64(b[24:], 77) // ino
		le.PutUint32(b[32:], 5)  // fd
		le.PutUint32(b[36:], op)
		le.PutUint32(b[40:], 9) // tgid
		le.PutUint32(b[44:], uint32(dfd))
		return b
	}

	ev, err := decodeIOEvent(hdr(IOOpWrite, 0))
	if err != nil {
		t.Fatal(err)
	}
	if ev.TsNs != 1 || ev.LatNs != 2 || ev.Bytes != 3 || ev.Ino != 77 || ev.FD != 5 || ev.Op != IOOpWrite || ev.TGID != 9 || ev.Path != "" {
		t.Errorf("write decoded as %+v", ev)
	}

	open := append(hdr(IOOpOpen, -100), make([]byte, ioPathMax)...)
	copy(open[ioEventSize:], "logs/app.log")
	ev, err = decodeIOEvent(open)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Op != IOOpOpen || ev.Dfd != -100 || ev.Path != "logs/app.log" || ev.Ino != 77 {
		t.Errorf("open decoded as %+v", ev)
	}

	if _, err := decodeIOEvent(hdr(IOOpOpen, -100)); err == nil {
		t.Error("an open without its path decoded")
	}
	if _, err := decodeIOEvent(make([]byte, ioEventSize-1)); err == nil {
		t.Error("a short record decoded")
	}
}
