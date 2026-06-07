package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/trentas/ptop/internal/bpf"
	"github.com/trentas/ptop/internal/serve"
	"github.com/trentas/ptop/internal/tui"
	"github.com/trentas/ptop/pkg/collector"
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
	serveAddr := flag.String("serve", "", "Headless mode: stream events over gRPC instead of the TUI (unix:///path or tcp://host:port)")
	showVer := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVer {
		fmt.Printf("ptop %s (commit %s, built %s)\n", version, commit, buildDate)
		os.Exit(0)
	}

	if *pid == 0 {
		fmt.Fprintln(os.Stderr, "error: --pid is required")
		fmt.Fprintln(os.Stderr, "usage: ptop --pid <PID> [--fps 5] [--no-ebpf] [--export]")
		fmt.Fprintln(os.Stderr, "       ptop --pid <PID> --serve unix:///run/ptop.sock")
		fmt.Fprintln(os.Stderr, "       ptop --version")
		os.Exit(1)
	}

	if !*noEBPF {
		// Build vs runtime diagnostic:
		//   - Available = false → binary was built WITHOUT `-tags=ebpf`.
		//     Not a permission error; it's the wrong build. Falls back to
		//     /proc on Linux, or to libproc on macOS (Tier 1, see #22).
		//   - Available = true but insufficient caps → fatal error before
		//     the TUI starts, with detailed message from Diagnose().
		if !bpf.Available {
			if runtime.GOOS == "darwin" {
				fmt.Fprintln(os.Stderr, "[ptop] macOS Tier 1 mode — collectors run via libproc + Mach.")
				fmt.Fprintln(os.Stderr, "       Some panels (syscalls F2, lock graph in F7, per-file I/O")
				fmt.Fprintln(os.Stderr, "       latency in F5) are structurally unavailable on macOS; see ?.")
			} else {
				fmt.Fprintln(os.Stderr, "[ptop] eBPF is not embedded in this binary")
				fmt.Fprintln(os.Stderr, "       Run `make build-ebpf` (Linux + libbpf-dev) to enable it.")
				fmt.Fprintln(os.Stderr, "       Continuing in /proc-only mode.")
			}
			fmt.Fprintln(os.Stderr, "")
		} else {
			caps := bpf.GetCapStatus()
			if diag := caps.Diagnose(); diag != "" {
				fmt.Fprintln(os.Stderr, "error: eBPF not available")
				fmt.Fprintln(os.Stderr, "")
				fmt.Fprint(os.Stderr, diag)
				os.Exit(1)
			}
			fmt.Fprintln(os.Stderr, "[ptop] eBPF embedded, kernel supports it. Starting tracers...")
		}
	}

	// Headless mode: serve the collector stream over gRPC instead of the TUI.
	if *serveAddr != "" {
		runServe(*serveAddr, *pid, *noEBPF)
		return
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

// runServe builds the collector Set and streams it over gRPC until SIGINT/
// SIGTERM. The Set's lifecycle is owned here: serve.Run only stops the server,
// so we stop the collectors after it returns.
func runServe(addr string, pid int, noEBPF bool) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	set := collector.NewSet(collector.SetConfig{PID: pid, NoEBPF: noEBPF})
	defer set.Stop()

	if err := serve.Run(ctx, addr, pid, set.Collectors()); err != nil {
		set.Stop() // os.Exit skips the defer
		fmt.Fprintf(os.Stderr, "fatal error: %v\n", err)
		os.Exit(1)
	}
}
