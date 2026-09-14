//go:build !linux

package symbol

import "errors"

// Symbolizer is unavailable off Linux: resolving a live process's addresses
// needs /proc/<pid>/maps. The ELF Module core (elf.go) still works everywhere.
type Symbolizer struct {
	// Present so Option (debuginfod.go) type-checks on every platform; the
	// off-ELF source is reached through Symbolize, which does not run here.
	debuginfod *Debuginfod
}

func NewSymbolizer(int, ...Option) (*Symbolizer, error) {
	return nil, errors.New("symbolizer requires /proc (Linux only)")
}

func (*Symbolizer) Symbolize(uint64) Frame { return Frame{} }
func (*Symbolizer) Close() error           { return nil }
func (*Symbolizer) ProcessBuildID() string { return "" }
