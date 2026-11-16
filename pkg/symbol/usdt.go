package symbol

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// USDTProbe is one site of a statically defined user probe (SystemTap SDT, the
// `.note.stapsdt` notes DTrace-style providers compile into a binary). A probe
// NAME can have several sites — one per place the compiler emitted the macro,
// inlined copies included — and every one must be attached for the probe to
// fire on every path.
//
// A site is a nop at Location; a uprobe placed there fires each time execution
// passes it. Nothing about the site needs the program's cooperation unless the
// probe is guarded by a semaphore, in which case the program only takes the
// probe's path while the semaphore is non-zero and the tracer must raise it
// (a uprobe's ref_ctr_offset, which the kernel then counts up and down).
type USDTProbe struct {
	Provider string
	Name     string
	// Args is the argument spec as the note carries it ("1@%dil", "-4@x1",
	// "8@$1"…), architecture-specific and unparsed.
	Args string

	// Location is the site's link-time virtual address, already corrected for
	// prelink (the note's base against .stapsdt.base's address).
	Location uint64
	// LocationOffset is the site's offset in the file, which is how a uprobe
	// names it.
	LocationOffset uint64
	// SemaphoreOffset is the file offset of the probe's semaphore, or 0 when
	// it has none (the common case: an unguarded probe fires whenever a uprobe
	// is placed on it).
	SemaphoreOffset uint64
}

// ntSTAPSDT is the note type of an SDT probe descriptor.
const ntSTAPSDT = 3

// ReadUSDTProbes returns every SDT probe site in the ELF image in r. It reads
// the program headers, the section headers, `.note.stapsdt` and the address of
// `.stapsdt.base`, and nothing else — never a symbol table — so it is cheap on
// a large library (libjvm.so is 20 MB, its notes 56 KB).
//
// An image with no probes returns an empty list and no error. A site whose
// address lands in no file-backed segment is an error rather than a skipped
// site: a provider attached at some sites and not others would under-count
// without saying so.
func ReadUSDTProbes(r io.ReaderAt) ([]USDTProbe, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("parse ELF: %w", err)
	}
	defer f.Close()

	sec := f.Section(".note.stapsdt")
	if sec == nil || sec.Type == elf.SHT_NOBITS {
		return nil, nil
	}
	data, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("read .note.stapsdt: %w", err)
	}
	var base uint64
	haveBase := false
	if b := f.Section(".stapsdt.base"); b != nil {
		base, haveBase = b.Addr, true
	}
	var loads []progLoad
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD {
			loads = append(loads, progLoad{off: p.Off, vaddr: p.Vaddr, filesz: p.Filesz})
		}
	}
	return parseSTAPSDTNotes(data, f.ByteOrder, f.Class == elf.ELFCLASS64, base, haveBase, loads)
}

// parseSTAPSDTNotes decodes a `.note.stapsdt` section. Each note's descriptor
// is three addresses (the site, the link-time address of .stapsdt.base, the
// semaphore; 8 bytes each in a 64-bit image, 4 in a 32-bit one) followed by
// three NUL-terminated strings: provider, name, argument spec.
//
// The site and the semaphore are recorded against the link-time base; when the
// image was prelinked, .stapsdt.base moved and both move with it by the same
// amount (the SystemTap convention, followed by every SDT consumer).
func parseSTAPSDTNotes(data []byte, bo binary.ByteOrder, is64 bool, base uint64, haveBase bool, loads []progLoad) ([]USDTProbe, error) {
	word := 4
	if is64 {
		word = 8
	}
	addr := func(b []byte) uint64 {
		if is64 {
			return bo.Uint64(b)
		}
		return uint64(bo.Uint32(b))
	}
	var out []USDTProbe
	for off := 0; off+12 <= len(data); {
		namesz := int(bo.Uint32(data[off : off+4]))
		descsz := int(bo.Uint32(data[off+4 : off+8]))
		ntype := bo.Uint32(data[off+8 : off+12])
		nameStart := off + 12
		descStart := nameStart + align4(namesz)
		descEnd := descStart + descsz
		if namesz < 0 || descsz < 0 || nameStart+namesz > len(data) || descEnd > len(data) {
			return nil, errors.New("truncated .note.stapsdt")
		}
		off = descStart + align4(descsz)
		name := string(data[nameStart : nameStart+namesz])
		if ntype != ntSTAPSDT || (name != "stapsdt\x00" && name != "stapsdt") {
			continue
		}
		desc := data[descStart:descEnd]
		if len(desc) < 3*word {
			return nil, fmt.Errorf("SDT note of %d bytes, want at least %d", len(desc), 3*word)
		}
		pc, linkBase, sem := addr(desc[0:]), addr(desc[word:]), addr(desc[2*word:])
		strs := splitNUL(desc[3*word:], 3)
		if len(strs) < 2 {
			return nil, errors.New("SDT note without a provider and a name")
		}
		p := USDTProbe{Provider: strs[0], Name: strs[1]}
		if len(strs) > 2 {
			p.Args = strs[2]
		}
		if haveBase && linkBase != 0 {
			pc += base - linkBase
			if sem != 0 {
				sem += base - linkBase
			}
		}
		p.Location = pc
		var ok bool
		if p.LocationOffset, ok = fileOffset(loads, pc); !ok {
			return nil, fmt.Errorf("SDT probe %s:%s at %#x is in no file-backed segment", p.Provider, p.Name, pc)
		}
		if sem != 0 {
			if p.SemaphoreOffset, ok = fileOffset(loads, sem); !ok {
				return nil, fmt.Errorf("SDT probe %s:%s has its semaphore at %#x, in no file-backed segment", p.Provider, p.Name, sem)
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// fileOffset converts a link-time virtual address to its file offset through
// the PT_LOAD headers; see Module.FileOffset.
func fileOffset(loads []progLoad, vaddr uint64) (uint64, bool) {
	for _, l := range loads {
		if vaddr >= l.vaddr && vaddr < l.vaddr+l.filesz {
			return vaddr - l.vaddr + l.off, true
		}
	}
	return 0, false
}

// splitNUL returns up to n NUL-terminated strings from b. A last string with no
// terminator is still returned.
func splitNUL(b []byte, n int) []string {
	var out []string
	for len(out) < n && len(b) > 0 {
		i := 0
		for i < len(b) && b[i] != 0 {
			i++
		}
		out = append(out, string(b[:i]))
		if i == len(b) {
			break
		}
		b = b[i+1:]
	}
	return out
}
