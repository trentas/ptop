package symbol

// Name → address lookup, the inverse of Resolve.
//
// Resolve answers "what code is at this address", which is what stack
// symbolization needs. Attaching a uprobe needs the opposite: "where does this
// named function start", and then where that lands in the FILE, since a uprobe
// is expressed as a path plus a file offset.
//
// Both directions must agree about stripped Go binaries. A release build with
// -ldflags="-s -w" has no .symtab at all, but it still carries .gopclntab —
// the Go runtime needs it for tracebacks, so it survives stripping. That is
// why the lookup below falls back to the line table rather than giving up: a
// production Go binary is very often exactly this case, and refusing it would
// mean the Go allocation axis only lit up for debug builds.

// IsGo reports whether the module carries a Go line table (.gopclntab), which
// is the reliable marker of a Go-compiled image: the runtime needs it for
// tracebacks, so it is present in stripped release builds too.
func (m *Module) IsGo() bool { return len(m.pclnData) > 0 }

// FuncStart returns the link-time virtual address and size of the named
// function.
//
// The ELF symbol table is consulted first (it carries a size, which the line
// table's entry/end pair only approximates), then the Go line table for
// stripped binaries. size is 0 when only the line table knew the symbol and
// its extent could not be derived.
func (m *Module) FuncStart(name string) (vaddr, size uint64, ok bool) {
	for _, f := range m.funcs {
		if f.name == name {
			return f.value, f.size, true
		}
	}
	if tab := m.gosym(); tab != nil {
		if fn := tab.LookupFunc(name); fn != nil {
			var sz uint64
			if fn.End > fn.Entry {
				sz = fn.End - fn.Entry
			}
			return fn.Entry, sz, true
		}
	}
	return 0, 0, false
}

// FileOffset converts a link-time virtual address to its offset within the
// file, which is the form a uprobe attachment takes (perf_event_open names a
// probe by inode + offset, not by runtime address).
//
// Returns ok=false for an address in no PT_LOAD segment, or in one whose
// content is not backed by the file at all (.bss — filesz < memsz), where a
// file offset would be meaningless.
func (m *Module) FileOffset(vaddr uint64) (uint64, bool) {
	for _, l := range m.loads {
		if vaddr >= l.vaddr && vaddr < l.vaddr+l.filesz {
			return vaddr - l.vaddr + l.off, true
		}
	}
	return 0, false
}
