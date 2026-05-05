//go:build linux && ebpf

package bpf

// Available é true quando o binário foi compilado com `-tags=ebpf` em Linux.
// Em qualquer outro build (default ou OS não-Linux) é false. main.go usa
// pra distinguir "eBPF tentou e falhou" de "binário sem eBPF".
const Available = true
