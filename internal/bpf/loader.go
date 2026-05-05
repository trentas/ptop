package bpf

// loader.go — carrega programas eBPF compilados e gerencia seu ciclo de vida.
//
// go:generate gera os binários .o a partir dos .c em programs/:
//go:generate make -C ../../../ gen

// Os objetos compilados são embarcados no binário via go:embed.
// Exemplo para syscalls:
//
//   //go:embed programs/syscalls.bpf.o
//   var syscallsBPFObj []byte
//
// Uso com libbpfgo:
//
//   import bpf "github.com/aquasecurity/libbpfgo"
//
//   func LoadSyscallsProgram(pid int) (*bpf.Module, error) {
//       m, err := bpf.NewModuleFromBuffer(syscallsBPFObj, "syscalls")
//       if err != nil {
//           return nil, err
//       }
//       if err := m.BPFLoadObject(); err != nil {
//           return nil, err
//       }
//       // setar PID no map target_pid
//       pidMap, _ := m.GetMap("target_pid")
//       key := uint32(0)
//       val := uint32(pid)
//       pidMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&val))
//
//       // attach tracepoints
//       for _, tp := range []string{"sys_enter", "sys_exit"} {
//           prog, _ := m.GetProgram("tracepoint__raw_syscalls__" + tp)
//           prog.AttachTracepoint("raw_syscalls", tp)
//       }
//       return m, nil
//   }
//
// TODO: implementar quando os .c estiverem compilando corretamente.
// Para MVP use --no-ebpf com leitura de /proc.
