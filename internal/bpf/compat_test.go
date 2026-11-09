package bpf

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestCompatExecutable(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if compatExecutable(self) {
		t.Error("the test binary, a 64-bit build, was reported as 32-bit")
	}

	// The smallest file debug/elf accepts as a 32-bit executable: an ELF32
	// header and nothing else.
	hdr := make([]byte, 52)
	copy(hdr, []byte{0x7f, 'E', 'L', 'F', 1 /* ELFCLASS32 */, 1 /* LSB */, 1 /* EV_CURRENT */})
	binary.LittleEndian.PutUint16(hdr[16:], 2)  // ET_EXEC
	binary.LittleEndian.PutUint16(hdr[18:], 3)  // EM_386
	binary.LittleEndian.PutUint32(hdr[20:], 1)  // EV_CURRENT
	binary.LittleEndian.PutUint16(hdr[40:], 52) // e_ehsize
	elf32 := filepath.Join(t.TempDir(), "elf32")
	if err := os.WriteFile(elf32, hdr, 0o755); err != nil {
		t.Fatal(err)
	}
	if !compatExecutable(elf32) {
		t.Error("an ELF32 executable was not reported as 32-bit")
	}

	notELF := filepath.Join(t.TempDir(), "script")
	if err := os.WriteFile(notELF, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if compatExecutable(notELF) {
		t.Error("a file that is not ELF was reported as 32-bit")
	}
	if compatExecutable(filepath.Join(t.TempDir(), "missing")) {
		t.Error("a missing file was reported as 32-bit")
	}
}
