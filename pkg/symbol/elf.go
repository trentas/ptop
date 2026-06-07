package symbol

import (
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"sync"
)

// Frame is a symbolized stack frame.
//
//   - Func is "" when the address couldn't be resolved to a function (a stripped
//     non-Go module); Module + Offset still locate it as "lib+0xNN".
//   - File/Line are populated only for Go modules (via .gopclntab) in this cut.
//     C/C++ file:line needs DWARF, which is deferred (#54 follow-up).
//   - Offset is module-relative (file vaddr − the module's load base), so it is
//     comparable across runs/ASLR.
type Frame struct {
	Func    string
	File    string
	Line    int
	Module  string
	Offset  uint64
	BuildID string
}

// funcSym is one STT_FUNC symbol, used for nearest-address lookup.
type funcSym struct {
	value uint64
	size  uint64
	name  string
}

// progLoad is the subset of a PT_LOAD program header needed to convert a file
// offset to a virtual address.
type progLoad struct {
	off, vaddr, filesz uint64
}

// Module wraps a parsed ELF image and resolves file virtual addresses to
// Frames. It retains no open file handle (all needed data is read at open
// time), so it is cheap to cache and safe for concurrent Resolve calls.
type Module struct {
	name     string
	funcs    []funcSym // sorted by value, deduped
	loads    []progLoad
	loadBase uint64 // smallest PT_LOAD vaddr (link-time base)
	buildID  string

	// gosym is built lazily on first use — parsing a large .gopclntab is
	// expensive and most modules are never the one a frame lands in.
	gosymOnce sync.Once
	gotab     *gosym.Table
	pclnData  []byte
	textAddr  uint64
}

// OpenModule parses the ELF image in r. name is used for Frame.Module (its
// basename) and error messages. r is fully consumed before returning; the
// caller may close it immediately.
func OpenModule(r io.ReaderAt, name string) (*Module, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("parse ELF %s: %w", name, err)
	}
	defer f.Close()

	m := &Module{name: filepath.Base(name), loadBase: ^uint64(0)}
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		m.loads = append(m.loads, progLoad{off: p.Off, vaddr: p.Vaddr, filesz: p.Filesz})
		if p.Vaddr < m.loadBase {
			m.loadBase = p.Vaddr
		}
	}
	if m.loadBase == ^uint64(0) {
		m.loadBase = 0
	}

	m.buildID = readBuildID(f)
	m.funcs = collectFuncs(f)

	// Stash the Go line table inputs for lazy gosym construction.
	if sec := f.Section(".gopclntab"); sec != nil {
		if data, err := sec.Data(); err == nil && len(data) > 0 {
			m.pclnData = data
			if t := f.Section(".text"); t != nil {
				m.textAddr = t.Addr
			}
		}
	}

	return m, nil
}

// Name returns the module basename.
func (m *Module) Name() string { return m.name }

// BuildID returns the GNU build-id (hex) or "" if absent.
func (m *Module) BuildID() string { return m.buildID }

// Resolve maps a file virtual address to a Frame. It tries, in order: the Go
// line table (func + file:line), the ELF symbol table (func name only), then a
// module+offset fallback for stripped binaries.
func (m *Module) Resolve(fileVaddr uint64) Frame {
	fr := Frame{Module: m.name, BuildID: m.buildID, Offset: fileVaddr - m.loadBase}

	if tab := m.gosym(); tab != nil {
		if file, line, fn := tab.PCToLine(fileVaddr); fn != nil {
			fr.Func, fr.File, fr.Line = fn.Name, file, line
			return fr
		}
	}
	if name, ok := lookupFunc(m.funcs, fileVaddr); ok {
		fr.Func = name
		return fr
	}
	return fr
}

func (m *Module) gosym() *gosym.Table {
	m.gosymOnce.Do(func() {
		if len(m.pclnData) == 0 {
			return
		}
		lt := gosym.NewLineTable(m.pclnData, m.textAddr)
		if tab, err := gosym.NewTable(nil, lt); err == nil {
			m.gotab = tab
		}
	})
	return m.gotab
}

// collectFuncs gathers STT_FUNC symbols from .symtab and .dynsym, sorted by
// address and deduped (the two tables overlap).
func collectFuncs(f *elf.File) []funcSym {
	var out []funcSym
	add := func(syms []elf.Symbol) {
		for _, s := range syms {
			if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Value == 0 || s.Name == "" {
				continue
			}
			out = append(out, funcSym{value: s.Value, size: s.Size, name: s.Name})
		}
	}
	if syms, err := f.Symbols(); err == nil {
		add(syms)
	}
	if dyn, err := f.DynamicSymbols(); err == nil {
		add(dyn)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].value != out[j].value {
			return out[i].value < out[j].value
		}
		return out[i].size > out[j].size // prefer the sized entry on a tie
	})
	// Dedupe identical addresses (keep the first, which has the larger size).
	deduped := out[:0]
	var last uint64 = ^uint64(0)
	for _, s := range out {
		if s.value == last {
			continue
		}
		deduped = append(deduped, s)
		last = s.value
	}
	return deduped
}

// lookupFunc finds the function containing addr by nearest-preceding address.
// A sized symbol bounds its range [value, value+size); a size-0 symbol (common
// for asm stubs) is attributed everything up to the next symbol.
func lookupFunc(funcs []funcSym, addr uint64) (string, bool) {
	if len(funcs) == 0 {
		return "", false
	}
	i := sort.Search(len(funcs), func(i int) bool { return funcs[i].value > addr }) - 1
	if i < 0 {
		return "", false
	}
	s := funcs[i]
	if s.size > 0 && addr >= s.value+s.size {
		return "", false // in the gap after a sized symbol
	}
	return s.name, true
}

// fileVaddr converts a runtime address (a VA in the target process) to the file
// virtual address the symbol table / gosym key on, using the maps segment that
// contained it plus the module's PT_LOAD headers. Works for PIE and non-PIE,
// the main executable and shared libraries.
func fileVaddr(runtimeAddr, segStart, segFileOff uint64, loads []progLoad) (uint64, bool) {
	fileOff := runtimeAddr - segStart + segFileOff
	for _, p := range loads {
		if fileOff >= p.off && fileOff < p.off+p.filesz {
			return fileOff - p.off + p.vaddr, true
		}
	}
	return 0, false
}

// readBuildID reads the GNU build-id from the .note.gnu.build-id section, or
// from a PT_NOTE segment when sections are stripped. Returns hex or "".
func readBuildID(f *elf.File) string {
	if s := f.Section(".note.gnu.build-id"); s != nil {
		if d, err := s.Data(); err == nil {
			if id := parseBuildIDNote(d, f.ByteOrder); id != "" {
				return id
			}
		}
	}
	for _, p := range f.Progs {
		if p.Type != elf.PT_NOTE {
			continue
		}
		d := make([]byte, p.Filesz)
		if _, err := io.ReadFull(p.Open(), d); err == nil {
			if id := parseBuildIDNote(d, f.ByteOrder); id != "" {
				return id
			}
		}
	}
	return ""
}

// parseBuildIDNote walks ELF notes (namesz, descsz, type, name, desc — each
// field 4-byte aligned) and returns the hex of the NT_GNU_BUILD_ID desc.
func parseBuildIDNote(data []byte, bo binary.ByteOrder) string {
	const ntGNUBuildID = 3
	for off := 0; off+12 <= len(data); {
		namesz := int(bo.Uint32(data[off : off+4]))
		descsz := int(bo.Uint32(data[off+4 : off+8]))
		ntype := bo.Uint32(data[off+8 : off+12])
		nameStart := off + 12
		descStart := nameStart + align4(namesz)
		descEnd := descStart + descsz
		if namesz < 0 || descsz < 0 || descEnd > len(data) || nameStart+namesz > len(data) {
			break
		}
		name := string(data[nameStart : nameStart+namesz])
		if ntype == ntGNUBuildID && (name == "GNU\x00" || name == "GNU") {
			return hex.EncodeToString(data[descStart:descEnd])
		}
		off = descStart + align4(descsz)
	}
	return ""
}

func align4(n int) int { return (n + 3) &^ 3 }
