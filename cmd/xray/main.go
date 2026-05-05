package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/trentas/xray/internal/bpf"
	"github.com/trentas/xray/internal/tui"
)

func main() {
	pid     := flag.Int("pid", 0, "PID do processo a inspecionar (obrigatório)")
	fps     := flag.Int("fps", 5, "Taxa de atualização da TUI (frames por segundo)")
	noEBPF := flag.Bool("no-ebpf", false, "Modo degradado: usa apenas /proc, sem eBPF (útil para desenvolvimento)")
	export  := flag.Bool("export", false, "Salvar snapshot JSON ao sair (equivalente à tecla 'e')")
	flag.Parse()

	if *pid == 0 {
		fmt.Fprintln(os.Stderr, "erro: --pid é obrigatório")
		fmt.Fprintln(os.Stderr, "uso:  xray --pid <PID> [--fps 5] [--no-ebpf]")
		os.Exit(1)
	}

	if !*noEBPF {
		caps := bpf.GetCapStatus()
		if diag := caps.Diagnose(); diag != "" {
			fmt.Fprintln(os.Stderr, "erro: eBPF não disponível")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprint(os.Stderr, diag)
			os.Exit(1)
		}
	}

	cfg := tui.Config{
		PID:    *pid,
		FPS:    *fps,
		NoEBPF: *noEBPF,
		Export: *export,
	}

	m := tui.NewModel(cfg)
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())

	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "erro fatal: %v\n", err)
		os.Exit(1)
	}

	// Cleanup + snapshot final no modo --export
	if fm, ok := finalModel.(tui.Model); ok {
		fm.Close()
		if cfg.Export {
			if path, err := tui.SaveSnapshot(fm); err == nil {
				fmt.Fprintf(os.Stderr, "snapshot final salvo: %s\n", path)
			} else {
				fmt.Fprintf(os.Stderr, "aviso: snapshot final falhou: %v\n", err)
			}
		}
	}
}
