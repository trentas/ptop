package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/yourusername/bpf-inspector/internal/tui"
)

func main() {
	pid     := flag.Int("pid", 0, "PID do processo a inspecionar (obrigatório)")
	fps     := flag.Int("fps", 5, "Taxa de atualização da TUI (frames por segundo)")
	noEBPF := flag.Bool("no-ebpf", false, "Modo degradado: usa apenas /proc, sem eBPF (útil para desenvolvimento)")
	export  := flag.Bool("export", false, "Salvar snapshot JSON ao sair (equivalente à tecla 'e')")
	flag.Parse()

	if *pid == 0 {
		fmt.Fprintln(os.Stderr, "erro: --pid é obrigatório")
		fmt.Fprintln(os.Stderr, "uso:  bpf-inspector --pid <PID> [--fps 5] [--no-ebpf]")
		os.Exit(1)
	}

	if !*noEBPF && os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "erro: eBPF requer root ou CAP_BPF")
		fmt.Fprintln(os.Stderr, "dica: use --no-ebpf para modo degradado sem root, ou execute com sudo")
		os.Exit(1)
	}

	cfg := tui.Config{
		PID:    *pid,
		FPS:    *fps,
		NoEBPF: *noEBPF,
		Export: *export,
	}

	m := tui.NewModel(cfg)
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "erro fatal: %v\n", err)
		os.Exit(1)
	}
}
