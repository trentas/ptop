//go:build linux

package bpf

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Capability bits do uapi/linux/capability.h relevantes pro xray.
const (
	capBPF       = 39
	capPerfmon   = 38
	capSysAdmin  = 21
	capSysPtrace = 19
)

// CapStatus descreve quais privilégios o processo atual tem em runtime,
// mais info de kernel/sysctl que afetam disponibilidade de eBPF.
type CapStatus struct {
	IsRoot       bool
	HasBPF       bool
	HasPerfmon   bool
	HasSysAdmin  bool
	HasSysPtrace bool

	// KernelMajor e KernelMinor são parseados de uname.release.
	// Vazios (=0) se a leitura falhou.
	KernelMajor int
	KernelMinor int

	// UnprivBPFDisabled é o valor de /proc/sys/kernel/unprivileged_bpf_disabled.
	// 0 = unprivileged eBPF permitido; 1/2 = bloqueado (default em distros modernas).
	// -1 = sysctl não pôde ser lido.
	UnprivBPFDisabled int
}

// GetCapStatus retorna o snapshot de privilégios do processo. Não falha:
// campos não-determináveis ficam zerados.
func GetCapStatus() CapStatus {
	s := CapStatus{
		IsRoot:            os.Geteuid() == 0,
		UnprivBPFDisabled: -1,
	}
	s.HasBPF = hasCapability(capBPF)
	s.HasPerfmon = hasCapability(capPerfmon)
	s.HasSysAdmin = hasCapability(capSysAdmin)
	s.HasSysPtrace = hasCapability(capSysPtrace)
	s.KernelMajor, s.KernelMinor = readKernelVersion()
	if data, err := os.ReadFile("/proc/sys/kernel/unprivileged_bpf_disabled"); err == nil {
		if v, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			s.UnprivBPFDisabled = v
		}
	}
	return s
}

// CanLoadBPF é true se o processo tem privilégios suficientes pra carregar
// programas eBPF (root OU CAP_BPF + CAP_PERFMON). Não considera kernel
// version — só capabilities.
func (s CapStatus) CanLoadBPF() bool {
	return s.IsRoot || (s.HasBPF && s.HasPerfmon)
}

// KernelSupportsBPF é true se kernel >= 5.8 (BTF + ring buffer + CAP_BPF).
// Versões anteriores funcionam parcialmente mas o xray assume 5.8+.
func (s CapStatus) KernelSupportsBPF() bool {
	if s.KernelMajor == 0 {
		return true // não sabemos; deixa o load falhar com erro mais específico
	}
	if s.KernelMajor > 5 {
		return true
	}
	return s.KernelMajor == 5 && s.KernelMinor >= 8
}

// Diagnose retorna uma mensagem multi-linha explicando o estado do processo
// e como obter privilégios eBPF (ou cair pra --no-ebpf). Vazio se está OK.
func (s CapStatus) Diagnose() string {
	if s.CanLoadBPF() && s.KernelSupportsBPF() {
		return ""
	}
	var b strings.Builder

	// Kernel issue tem prioridade — não adianta sugerir caps se kernel é antigo
	if !s.KernelSupportsBPF() {
		fmt.Fprintf(&b, "Kernel %d.%d detectado — xray requer Linux 5.8+ (BTF + CAP_BPF).\n",
			s.KernelMajor, s.KernelMinor)
		fmt.Fprintln(&b, "Em kernels antigos, use --no-ebpf (modo /proc-only).")
		return b.String()
	}

	fmt.Fprintln(&b, "eBPF não disponível com privilégios atuais.")

	// Quais caps estão faltando?
	missing := []string{}
	if !s.HasBPF {
		missing = append(missing, "CAP_BPF")
	}
	if !s.HasPerfmon {
		missing = append(missing, "CAP_PERFMON")
	}
	if len(missing) > 0 && !s.IsRoot {
		fmt.Fprintf(&b, "Faltando: %s\n", strings.Join(missing, ", "))
	}

	if s.UnprivBPFDisabled > 0 && !s.IsRoot {
		fmt.Fprintln(&b, "")
		fmt.Fprintf(&b, "Aviso: kernel.unprivileged_bpf_disabled=%d — eBPF unprivileged bloqueado.\n",
			s.UnprivBPFDisabled)
		fmt.Fprintln(&b, "Pra reverter (temporariamente): sudo sysctl kernel.unprivileged_bpf_disabled=0")
	}

	fmt.Fprintln(&b, "")
	fmt.Fprintln(&b, "Opções:")
	fmt.Fprintln(&b, "  1) Execute com sudo:")
	fmt.Fprintln(&b, "       sudo ./bin/xray --pid <PID>")
	fmt.Fprintln(&b, "  2) Aplique caps no binário (uma vez):")
	fmt.Fprintln(&b, "       sudo setcap cap_bpf,cap_perfmon+ep ./bin/xray")
	fmt.Fprintln(&b, "  3) Modo /proc-only (sem eBPF, sem privilégios):")
	fmt.Fprintln(&b, "       ./bin/xray --pid <PID> --no-ebpf")

	return b.String()
}

// hasCapability lê /proc/self/status (campo CapEff) e testa o bit do cap.
// Retorna false em qualquer erro.
func hasCapability(capBit int) bool {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		hexStr := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		eff, err := strconv.ParseUint(hexStr, 16, 64)
		if err != nil {
			return false
		}
		return eff&(uint64(1)<<uint(capBit)) != 0
	}
	return false
}

// readKernelVersion parseia "X.Y" do começo de /proc/sys/kernel/osrelease.
func readKernelVersion() (major, minor int) {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return 0, 0
	}
	s := strings.TrimSpace(string(data))
	// Formato: "5.15.0-91-generic" → major=5, minor=15
	parts := strings.SplitN(s, ".", 3)
	if len(parts) < 2 {
		return 0, 0
	}
	major, _ = strconv.Atoi(parts[0])
	minor, _ = strconv.Atoi(parts[1])
	return major, minor
}
