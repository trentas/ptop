package symbol

import (
	"debug/dwarf"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"runtime/debug"
	"sort"
	"sync"
)

// Frame is a symbolized stack frame.
//
//   - Func is "" when the address couldn't be resolved to a function (a stripped
//     non-Go module); Module + Offset still locate it as "lib+0xNN".
//   - File/Line come from .gopclntab for Go modules and from DWARF line info
//     for C/C++. They stay empty for a module built without debug info, which
//     is most shipped C/C++ binaries.
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

// Module is one name for a parsed ELF image, and resolves file virtual
// addresses in it to Frames. It retains no open file handle, so it is cheap to
// cache and safe for concurrent Resolve calls.
//
// The name is the only thing a Module owns. Everything parsed out of the file
// lives in the image, which depends on the file's contents alone, so every
// Module opened on the same file shares one (image.go, #137): the four
// symbolizing collectors of a target, the Go allocation probe locating
// runtime.mallocgc, and the symbolizers of a second target running the same
// binary. The name stays per Module because callers reach one file by
// different paths — /proc/<pid>/exe and the mapped path name the same image,
// and Frame.Module must not depend on which of them opened it first.
type Module struct {
	name string
	*image
}

// image is everything parsed out of one ELF file. Read-only once built, apart
// from the lazily constructed line tables, which guard themselves.
type image struct {
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

	// DWARF line info for C/C++ file:line, built lazily for the same reason
	// (see dwarf.go). dwarfMu guards the stateful readers.
	dwarfSecs   map[string][]byte
	dwarfOnce   sync.Once
	dw          *dwarf.Data
	dwarfMu     sync.Mutex
	lineReaders map[dwarf.Offset]*dwarf.LineReader

	// mapping is the file, mapped read-only, when pclnData and dwarfSecs are
	// slices of it rather than heap copies; nil when they are copies. It is
	// unmapped by a cleanup once no Module references the image, and every
	// method that reads it runs under a fault guard — see image.go.
	mapping   []byte
	faultOnce sync.Once
}

// OpenModule parses the ELF image in r. name is used for Frame.Module (its
// basename) and error messages. The caller may close r as soon as this returns.
//
// When r is an *os.File the parse is shared: a file already open as a Module
// elsewhere in the process is not parsed again, and the large sections are
// mapped from the file instead of copied onto the heap. Any other ReaderAt is
// parsed afresh into heap copies. See image.go for both.
func OpenModule(r io.ReaderAt, name string) (*Module, error) {
	img, err := loadImage(r, name)
	if err != nil {
		return nil, err
	}
	return &Module{name: filepath.Base(name), image: img}, nil
}

// parseImage does the parsing for OpenModule. Section contents come through
// data, which slices them out of a mapping of the file when it can and copies
// them otherwise (sectionSource, image.go).
func parseImage(r io.ReaderAt, name string, data func(*elf.Section) ([]byte, error)) (*image, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, fmt.Errorf("parse ELF %s: %w", name, err)
	}
	defer f.Close()

	m := &image{loadBase: ^uint64(0)}
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
	m.dwarfSecs = loadDWARFSections(f, data)

	// Stash the Go line table inputs for lazy gosym construction.
	//
	// SHT_NOBITS is skipped throughout: a separate debug image (#119) keeps
	// every allocated section's header while blanking its contents, and
	// Section.Data on one of those hands back a zero-filled buffer the size of
	// the original — a large allocation that can only parse as garbage.
	if sec := f.Section(".gopclntab"); sec != nil && sec.Type != elf.SHT_NOBITS {
		if d, err := data(sec); err == nil && len(d) > 0 {
			m.pclnData = d
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
// line table (func + file:line), the ELF symbol table plus DWARF (func name,
// and file:line where debug info is present), then a module+offset fallback
// for stripped binaries.
//
// The two file:line sources are kept apart on purpose. .gopclntab is compact,
// always present in a Go image, and authoritative there — it is consulted
// first and short-circuits. DWARF is the C/C++ path: optional, much larger,
// and absent from most shipped binaries, so it runs only after a name has
// already been found and only fills in what is missing.
//
// A fault reading the mapped file — it was truncated on disk while mapped —
// ends the lookup with whatever had resolved so far rather than the process
// (endFaultGuard).
func (m *Module) Resolve(fileVaddr uint64) (fr Frame) {
	fr = Frame{Module: m.name, BuildID: m.buildID, Offset: fileVaddr - m.loadBase}
	if m.mapping != nil {
		defer m.endFaultGuard(m.name, debug.SetPanicOnFault(true))
	}

	if tab := m.gosym(); tab != nil {
		if file, line, fn := tab.PCToLine(fileVaddr); fn != nil {
			// goSourcePath: the line table records the BUILD machine's path,
			// which does not travel (#107) — key on the import path instead.
			fr.Func, fr.File, fr.Line = fn.Name, goSourcePath(fn.Name, file), line
			return fr
		}
	}
	if name, ok := lookupFunc(m.funcs, fileVaddr); ok {
		fr.Func = name
	}
	if file, line, ok := m.dwarfLine(fileVaddr); ok {
		fr.File, fr.Line = file, line
	}
	return fr
}

func (m *image) gosym() *gosym.Table {
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

// fileBuildID reads the GNU build-id of the ELF image in r, or "". It parses
// the headers and one note and nothing else — never the symbol tables or the
// line table — which is what makes it cheap enough to call for an identity
// (#137: ProcessBuildID used to open a full Module for it, and on a Go binary
// that meant a copy of .gopclntab to read 20 bytes).
func fileBuildID(r io.ReaderAt) string {
	f, err := elf.NewFile(r)
	if err != nil {
		return ""
	}
	defer f.Close()
	return readBuildID(f)
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
