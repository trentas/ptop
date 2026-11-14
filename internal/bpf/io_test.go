//go:build linux && ebpf

package bpf

import (
	"encoding/binary"
	"testing"
)

// decodeIORecord reads the layout io.bpf.c writes: struct io_record, then for
// an open the path (#162) and for a close the key's io_stat (#181).
func TestDecodeIORecord(t *testing.T) {
	le := binary.LittleEndian
	hdr := func(kind uint32, dfd int32) []byte {
		b := make([]byte, ioRecordSize)
		le.PutUint32(b[0:], kind)
		le.PutUint32(b[4:], 9) // tgid
		le.PutUint32(b[8:], 5) // fd
		le.PutUint32(b[12:], uint32(dfd))
		le.PutUint64(b[16:], 77) // ino
		le.PutUint64(b[24:], 42) // gen
		return b
	}

	r, err := decodeIORecord(hdr(IORecSeen, 0))
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != IORecSeen || r.TGID != 9 || r.FD != 5 || r.Ino != 77 || r.Gen != 42 || r.Path != "" {
		t.Errorf("seen decoded as %+v", r)
	}
	if r.Key() != (IOKey{TGID: 9, FD: 5, Ino: 77}) {
		t.Errorf("key %+v", r.Key())
	}

	open := append(hdr(IORecOpen, -100), make([]byte, ioPathMax)...)
	copy(open[ioRecordSize:], "logs/app.log")
	r, err = decodeIORecord(open)
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != IORecOpen || r.Dfd != -100 || r.Path != "logs/app.log" || r.Ino != 77 {
		t.Errorf("open decoded as %+v", r)
	}

	closed := append(hdr(IORecClose, 0), make([]byte, ioStatSize)...)
	for i, v := range []uint64{42, 3, 4, 700, 9000} {
		le.PutUint64(closed[ioRecordSize+8*i:], v)
	}
	r, err = decodeIORecord(closed)
	if err != nil {
		t.Fatal(err)
	}
	if r.Stat != (IOStat{Gen: 42, Reads: 3, Writes: 4, Bytes: 700, LatNs: 9000}) {
		t.Errorf("close decoded as %+v", r.Stat)
	}

	for name, raw := range map[string][]byte{
		"an open without its path":    hdr(IORecOpen, -100),
		"a close without its counts":  hdr(IORecClose, 0),
		"a short header":              make([]byte, ioRecordSize-1),
		"a record of an unknown kind": hdr(7, 0),
	} {
		if _, err := decodeIORecord(raw); err == nil {
			t.Errorf("%s decoded", name)
		}
	}
}
