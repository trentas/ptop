//go:build !linux || !ebpf

package bpf

import "errors"

// Stub para builds sem `-tags=ebpf` (default) ou em OS não-Linux (macOS/Windows).
// Mesma interface da versão Linux+ebpf — todos os Load* retornam um erro
// uniforme indicando que o subsystem eBPF não está disponível neste build.
//
// Isto permite que o resto do projeto importe `internal/bpf` sem quebrar
// compilação no macOS, e que o codepath de runtime detecte graciosamente
// que precisa cair pra /proc collectors.

var errStub = errors.New("eBPF não disponível neste build (precisa Linux + -tags=ebpf)")

type Loader struct{}

func NewLoader() *Loader                 { return &Loader{} }
func (*Loader) LoadSyscalls(int) error   { return errStub }
func (*Loader) LoadCPU(int) error        { return errStub }
func (*Loader) LoadIO(int) error         { return errStub }
func (*Loader) LoadNetwork(int) error    { return errStub }
func (*Loader) LoadSched(int) error      { return errStub }
func (*Loader) LoadMemory(int) error     { return errStub }
