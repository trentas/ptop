package symbol

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// sdtNote builds one `.note.stapsdt` entry the way <sys/sdt.h> emits it.
func sdtNote(bo binary.ByteOrder, is64 bool, pc, base, sem uint64, provider, name, args string) []byte {
	var desc bytes.Buffer
	for _, a := range []uint64{pc, base, sem} {
		if is64 {
			_ = binary.Write(&desc, bo, a)
		} else {
			_ = binary.Write(&desc, bo, uint32(a))
		}
	}
	desc.WriteString(provider + "\x00" + name + "\x00" + args + "\x00")
	return rawNote(bo, ntSTAPSDT, "stapsdt\x00", desc.Bytes())
}

func rawNote(bo binary.ByteOrder, typ uint32, name string, desc []byte) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, bo, uint32(len(name)))
	_ = binary.Write(&b, bo, uint32(len(desc)))
	_ = binary.Write(&b, bo, typ)
	b.WriteString(name)
	b.Write(make([]byte, align4(len(name))-len(name)))
	b.Write(desc)
	b.Write(make([]byte, align4(len(desc))-len(desc)))
	return b.Bytes()
}

// The layout of libjvm.so as Temurin 21 ships it on arm64: text mapped at
// offset == vaddr, data one page-aligned segment up, .stapsdt.base where the
// notes say it is.
var jvmLoads = []progLoad{
	{off: 0, vaddr: 0, filesz: 0x12af998},
	{off: 0x12b20a0, vaddr: 0x12c20a0, filesz: 0x10fe68},
}

func TestParseSTAPSDTNotesReadsEverySite(t *testing.T) {
	bo := binary.LittleEndian
	const base = 0x1049798
	var data []byte
	data = append(data, sdtNote(bo, true, 0x7a33d0, base, 0, "hotspot", "gc__begin", "1@1")...)
	data = append(data, sdtNote(bo, true, 0x7a340c, base, 0, "hotspot", "gc__end", "")...)
	// A note of another kind between two probes is skipped, not misread.
	data = append(data, rawNote(bo, 3, "GNU\x00", []byte{1, 2, 3, 4})...)
	data = append(data, sdtNote(bo, true, 0x7a3524, base, 0, "hotspot", "gc__begin", "1@x0")...)

	got, err := parseSTAPSDTNotes(data, bo, true, base, true, jvmLoads)
	if err != nil {
		t.Fatal(err)
	}
	want := []USDTProbe{
		{Provider: "hotspot", Name: "gc__begin", Args: "1@1", Location: 0x7a33d0, LocationOffset: 0x7a33d0},
		{Provider: "hotspot", Name: "gc__end", Location: 0x7a340c, LocationOffset: 0x7a340c},
		{Provider: "hotspot", Name: "gc__begin", Args: "1@x0", Location: 0x7a3524, LocationOffset: 0x7a3524},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d probes, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("probe %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// A semaphore lives in the data segment, whose file offset is not its address:
// the uprobe's ref_ctr_offset is the file offset, so the conversion must use
// the segment the semaphore is in, not the one the site is in.
func TestParseSTAPSDTNotesConvertsTheSemaphoreThroughItsOwnSegment(t *testing.T) {
	bo := binary.LittleEndian
	const base, sem = 0x1049798, 0x12c3000
	data := sdtNote(bo, true, 0x7a33d0, base, sem, "hotspot", "method__entry", "")
	got, err := parseSTAPSDTNotes(data, bo, true, base, true, jvmLoads)
	if err != nil {
		t.Fatal(err)
	}
	if want := uint64(sem - 0x12c20a0 + 0x12b20a0); got[0].SemaphoreOffset != want {
		t.Errorf("semaphore offset = %#x, want %#x", got[0].SemaphoreOffset, want)
	}
}

// A prelinked image moved .stapsdt.base; the site and the semaphore move with
// it by the same amount.
func TestParseSTAPSDTNotesFollowsAPrelinkedBase(t *testing.T) {
	bo := binary.LittleEndian
	const linkBase, movedBy = 0x1049798, 0x1000
	loads := []progLoad{{off: 0, vaddr: 0, filesz: 0x2000000}}
	data := sdtNote(bo, true, 0x7a33d0, linkBase, 0x1b00000, "p", "n", "")
	got, err := parseSTAPSDTNotes(data, bo, true, linkBase+movedBy, true, loads)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Location != 0x7a33d0+movedBy || got[0].SemaphoreOffset != 0x1b00000+movedBy {
		t.Errorf("site %#x, semaphore %#x: want both moved by %#x", got[0].Location, got[0].SemaphoreOffset, movedBy)
	}
}

func TestParseSTAPSDTNotes32Bit(t *testing.T) {
	bo := binary.BigEndian
	loads := []progLoad{{off: 0x100, vaddr: 0x10000, filesz: 0x1000}}
	data := sdtNote(bo, false, 0x10040, 0, 0, "prov", "probe", "-4@%eax")
	got, err := parseSTAPSDTNotes(data, bo, false, 0, false, loads)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "probe" || got[0].Args != "-4@%eax" || got[0].LocationOffset != 0x140 {
		t.Errorf("got %+v", got)
	}
}

// A site that cannot be placed fails the whole read: attaching at some sites
// of a probe and not others would under-count it without saying so.
func TestParseSTAPSDTNotesRefusesASiteOutsideTheFile(t *testing.T) {
	bo := binary.LittleEndian
	data := sdtNote(bo, true, 0x9000000, 0, 0, "hotspot", "gc__end", "")
	_, err := parseSTAPSDTNotes(data, bo, true, 0, false, jvmLoads)
	if err == nil || !strings.Contains(err.Error(), "gc__end") {
		t.Fatalf("err = %v, want one naming the probe", err)
	}
}

func TestParseSTAPSDTNotesRefusesATruncatedNote(t *testing.T) {
	bo := binary.LittleEndian
	data := sdtNote(bo, true, 0x7a33d0, 0, 0, "hotspot", "gc__end", "")
	if _, err := parseSTAPSDTNotes(data[:len(data)-12], bo, true, 0, false, jvmLoads); err == nil {
		t.Fatal("a truncated note parsed")
	}
}
