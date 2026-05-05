//go:build linux && ebpf

package bpf

import (
	_ "embed"
	"bytes"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// syscallsBPFObj é o objeto BPF compilado a partir de programs/syscalls.bpf.c.
// Gerado por `make gen` (clang -target bpf -c).
//
//go:embed programs/syscalls.bpf.o
var syscallsBPFObj []byte

// SyscallStat espelha `struct syscall_stat` em syscalls.bpf.c.
// O layout precisa bater byte-a-byte com o C struct (8+8 bytes, sem padding).
type SyscallStat struct {
	Count      uint64
	TotalLatNs uint64
}

// SyscallTracer carrega o programa eBPF de syscalls, attacha nos tracepoints
// raw_syscalls/sys_{enter,exit}, e expõe métodos pra ler o map de contagens.
//
// Lifecycle:
//   t, err := OpenSyscallTracer(pid)
//   defer t.Close()                  // detacha programs + libera maps
//   stats, _ := t.Stats()            // snapshot do map syscall_count
type SyscallTracer struct {
	coll        *ebpf.Collection
	enterLink   link.Link
	exitLink    link.Link
	syscallMap  *ebpf.Map
}

// OpenSyscallTracer abre o tracer pro PID alvo. Falha se kernel não suporta
// eBPF tracepoints, se faltam capabilities, ou se o objeto BPF não bateu na
// verificação do kernel.
func OpenSyscallTracer(pid int) (*SyscallTracer, error) {
	if pid <= 0 {
		return nil, errors.New("pid inválido")
	}
	// Aumenta o RLIMIT_MEMLOCK pra que o kernel aceite alocações de map.
	// Em kernels 5.11+ com BPF memcg, isso é no-op mas continua seguro.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit.RemoveMemlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(syscallsBPFObj))
	if err != nil {
		return nil, fmt.Errorf("parse BPF object: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load BPF collection: %w", err)
	}

	t := &SyscallTracer{coll: coll}

	// Configura o map target_pid com o PID alvo (key=0 → val=pid).
	targetMap := coll.Maps["target_pid"]
	if targetMap == nil {
		t.Close()
		return nil, errors.New("target_pid map não encontrado no objeto BPF")
	}
	var key uint32 = 0
	val := uint32(pid)
	if err := targetMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
		t.Close()
		return nil, fmt.Errorf("set target_pid: %w", err)
	}

	t.syscallMap = coll.Maps["syscall_count"]
	if t.syscallMap == nil {
		t.Close()
		return nil, errors.New("syscall_count map não encontrado")
	}

	enterProg := coll.Programs["handle_sys_enter"]
	exitProg := coll.Programs["handle_sys_exit"]
	if enterProg == nil || exitProg == nil {
		t.Close()
		return nil, errors.New("programs handle_sys_enter/exit não encontrados")
	}

	// Attacha nos tracepoints. Esta operação é o que efetivamente liga o
	// programa ao kernel; até aqui ele só estava carregado.
	enterLink, err := link.Tracepoint("raw_syscalls", "sys_enter", enterProg, nil)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("attach sys_enter: %w", err)
	}
	t.enterLink = enterLink

	exitLink, err := link.Tracepoint("raw_syscalls", "sys_exit", exitProg, nil)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("attach sys_exit: %w", err)
	}
	t.exitLink = exitLink

	return t, nil
}

// Stats retorna um snapshot do map syscall_count: syscall_id → {count, lat_total}.
// Iteração é segura mesmo enquanto o BPF program escreve concorrentemente
// (pode pular ou repetir entries marginais — aceitável pra UI).
func (t *SyscallTracer) Stats() (map[uint32]SyscallStat, error) {
	if t == nil || t.syscallMap == nil {
		return nil, errors.New("tracer não inicializado")
	}
	out := make(map[uint32]SyscallStat, 64)
	var key uint32
	var val SyscallStat
	iter := t.syscallMap.Iterate()
	for iter.Next(&key, &val) {
		out[key] = val
	}
	if err := iter.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// Close detacha os programs, libera maps e devolve recursos do kernel.
// Idempotente; pode ser chamado múltiplas vezes.
func (t *SyscallTracer) Close() error {
	if t == nil {
		return nil
	}
	var errs []error
	if t.enterLink != nil {
		if err := t.enterLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close sys_enter link: %w", err))
		}
		t.enterLink = nil
	}
	if t.exitLink != nil {
		if err := t.exitLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close sys_exit link: %w", err))
		}
		t.exitLink = nil
	}
	if t.coll != nil {
		t.coll.Close()
		t.coll = nil
		t.syscallMap = nil
	}
	return errors.Join(errs...)
}
