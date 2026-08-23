package symbol

import (
	"debug/dwarf"
	"debug/elf"
)

// DWARF line resolution — file:line for C/C++, the follow-up this package's
// doc comment has been deferring.
//
// Go binaries already get file:line from .gopclntab, which is compact and
// always present. Nothing equivalent exists for C/C++: the function name comes
// from .symtab, and the source location lives only in DWARF. Without it a
// contended lock or a hot allocation site in a C service resolves to a bare
// function name — enough to say WHAT, never enough to point at a line, and a
// line is what a consumer needs to cross the behaviour against a code diff.
//
// ─── Why the sections are copied in, and why there is a budget ──────────────
//
// A Module deliberately retains no open file handle, so it stays cheap to
// cache and safe to share. Keeping that property means the DWARF bytes have to
// be copied in while the file is open, and parsed later on demand.
//
// Copying is bounded because it is unbounded in principle: a large C++ binary
// built with -g carries debug sections far larger than its code. Past the
// budget the module simply resolves without file:line — the same answer it
// gave before this file existed, which is a real degradation but a safe one.
// The alternative (holding a file handle per mapped module for the life of the
// process) trades a bounded memory cost for an unbounded fd cost.
//
// .debug_frame and the location lists are not copied: they carry unwind and
// variable-location data, they are often the largest sections present, and the
// line table needs neither.

// dwarfBudget caps the total debug bytes copied into one Module. Sized so an
// ordinary service binary with -g fits comfortably while a debug-info-heavy
// C++ image degrades to func-only instead of pinning hundreds of megabytes.
const dwarfBudget = 256 << 20

// dwarfSections are the sections a line lookup needs: the DIE tree to find the
// compile unit covering an address (info/abbrev/ranges/rnglists/addr), the
// line program itself (line), and the string tables DWARF 5 splits names into
// (str/line_str/str_offsets).
var dwarfSections = []string{
	".debug_abbrev",
	".debug_addr",
	".debug_info",
	".debug_line",
	".debug_line_str",
	".debug_ranges",
	".debug_rnglists",
	".debug_str",
	".debug_str_offsets",
}

// loadDWARFSections copies the line-resolution sections out of f, or returns
// nil when the image has no debug info or exceeds the budget.
func loadDWARFSections(f *elf.File) map[string][]byte {
	var total uint64
	for _, name := range dwarfSections {
		if sec := f.Section(name); sec != nil {
			total += sec.Size
		}
	}
	if total == 0 || total > dwarfBudget {
		return nil
	}
	// .debug_info and .debug_line are the two that must be there; without
	// either there is no line program to read and the copy is wasted.
	if f.Section(".debug_info") == nil || f.Section(".debug_line") == nil {
		return nil
	}

	out := make(map[string][]byte, len(dwarfSections))
	for _, name := range dwarfSections {
		sec := f.Section(name)
		if sec == nil {
			continue
		}
		data, err := sec.Data()
		if err != nil {
			continue // a compressed or truncated section: skip it, not the lot
		}
		out[name] = data
	}
	if out[".debug_info"] == nil || out[".debug_line"] == nil {
		return nil
	}
	return out
}

// dwarfData builds the DWARF reader on first use. Parsing is deferred because
// most modules in a process never have a frame land in them.
func (m *Module) dwarfData() *dwarf.Data {
	m.dwarfOnce.Do(func() {
		if len(m.dwarfSecs) == 0 {
			return
		}
		sec := func(name string) []byte { return m.dwarfSecs[name] }
		d, err := dwarf.New(
			sec(".debug_abbrev"),
			nil, // .debug_aranges: an index we don't use; SeekPC walks the DIEs
			nil, // .debug_frame: unwind data, not line data
			sec(".debug_info"),
			sec(".debug_line"),
			nil, // .debug_pubnames: superseded, and not needed for a line lookup
			sec(".debug_ranges"),
			sec(".debug_str"),
		)
		if err != nil {
			return
		}
		// DWARF 5 moved parts of the line program's strings and the address
		// and range lists into their own sections. dwarf.New predates them, so
		// they are attached separately; a failure here is not fatal, it just
		// limits which units resolve.
		for _, name := range []string{".debug_line_str", ".debug_str_offsets", ".debug_addr", ".debug_rnglists"} {
			if data := sec(name); len(data) > 0 {
				_ = d.AddSection(name, data)
			}
		}
		m.dw = d
	})
	return m.dw
}

// dwarfLine resolves a link-time virtual address to its source file and line
// via the DWARF line program. ok is false when the module carries no usable
// debug info or no line covers the address.
//
// Serialized on m.dwarfMu: dwarf.Reader and dwarf.LineReader are stateful
// cursors, and Module.Resolve is documented safe for concurrent use.
func (m *Module) dwarfLine(fileVaddr uint64) (file string, line int, ok bool) {
	d := m.dwarfData()
	if d == nil {
		return "", 0, false
	}

	m.dwarfMu.Lock()
	defer m.dwarfMu.Unlock()

	cu, err := d.Reader().SeekPC(fileVaddr)
	if err != nil || cu == nil {
		return "", 0, false
	}

	// The line program is parsed once per compile unit and the cursor reused:
	// re-reading the header for every frame that lands in the same unit is the
	// difference between a lookup and a re-parse, and stacks cluster heavily
	// into a handful of units.
	lr, cached := m.lineReaders[cu.Offset]
	if !cached {
		lr, err = d.LineReader(cu)
		if err != nil || lr == nil {
			return "", 0, false
		}
		if m.lineReaders == nil {
			m.lineReaders = make(map[dwarf.Offset]*dwarf.LineReader, 4)
		}
		m.lineReaders[cu.Offset] = lr
	}

	var ent dwarf.LineEntry
	if err := lr.SeekPC(fileVaddr, &ent); err != nil {
		return "", 0, false
	}
	if ent.File == nil || ent.File.Name == "" || ent.Line <= 0 {
		return "", 0, false
	}
	return ent.File.Name, ent.Line, true
}
