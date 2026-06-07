//go:build !linux

package symbol

import "errors"

// Symbolizer is unavailable off Linux: resolving a live process's addresses
// needs /proc/<pid>/maps. The ELF Module core (elf.go) still works everywhere.
type Symbolizer struct{}

func NewSymbolizer(int) (*Symbolizer, error) {
	return nil, errors.New("symbolizer requires /proc (Linux only)")
}

func (*Symbolizer) Symbolize(uint64) Frame { return Frame{} }
func (*Symbolizer) Close() error           { return nil }
func (*Symbolizer) ProcessBuildID() string { return "" }
