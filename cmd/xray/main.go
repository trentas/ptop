package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/trentas/xray/internal/bpf"
	"github.com/trentas/xray/internal/tui"
)

// Variables injected via -ldflags in the release build (goreleaser).
// In dev (`go build`/`go run`), they stay as "dev"/"none"/"unknown".
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func main() {
	pid := flag.Int("pid", 0, "PID of the process to inspect (required)")
	fps := flag.Int("fps", 5, "TUI refresh rate (frames per second)")
	noEBPF := flag.Bool("no-ebpf", false, "Degraded mode: use only /proc, no eBPF (useful for development)")
	export := flag.Bool("export", false, "Save JSON snapshot on exit (equivalent to the 'e' key)")
	showVer := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVer {
		fmt.Printf("xray %s (commit %s, built %s)\n", version, commit, buildDate)
		os.Exit(0)
	}

	if *pid == 0 {
		fmt.Fprintln(os.Stderr, "error: --pid is required")
		fmt.Fprintln(os.Stderr, "usage: xray --pid <PID> [--fps 5] [--no-ebpf] [--export]")
		fmt.Fprintln(os.Stderr, "       xray --version")
		os.Exit(1)
	}

	if !*noEBPF {
		// Build vs runtime diagnostic:
		//   - Available = false → binary was built WITHOUT `-tags=ebpf`.
		//     Not a permission error; it's the wrong build. Falls back to /proc.
		//   - Available = true but insufficient caps → fatal error before
		//     the TUI starts, with detailed message from Diagnose().
		if !bpf.Available {
			fmt.Fprintln(os.Stderr, "[xray] eBPF is not embedded in this binary")
			fmt.Fprintln(os.Stderr, "       Run `make build-ebpf` (Linux + libbpf-dev) to enable it.")
			fmt.Fprintln(os.Stderr, "       Continuing in /proc-only mode.")
			fmt.Fprintln(os.Stderr, "")
		} else {
			caps := bpf.GetCapStatus()
			if diag := caps.Diagnose(); diag != "" {
				fmt.Fprintln(os.Stderr, "error: eBPF not available")
				fmt.Fprintln(os.Stderr, "")
				fmt.Fprint(os.Stderr, diag)
				os.Exit(1)
			}
			fmt.Fprintln(os.Stderr, "[xray] eBPF embedded, kernel supports it. Starting tracers...")
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
		fmt.Fprintf(os.Stderr, "fatal error: %v\n", err)
		os.Exit(1)
	}

	// Cleanup + final snapshot in --export mode
	if fm, ok := finalModel.(tui.Model); ok {
		fm.Close()
		if cfg.Export {
			if path, err := tui.SaveSnapshot(fm); err == nil {
				fmt.Fprintf(os.Stderr, "final snapshot saved: %s\n", path)
			} else {
				fmt.Fprintf(os.Stderr, "warning: final snapshot failed: %v\n", err)
			}
		}
	}
}
