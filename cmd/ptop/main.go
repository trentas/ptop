package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof" // registers /debug/pprof handlers on http.DefaultServeMux
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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
	tls := flag.Bool("tls", false, "Capture TLS payload metadata (direction/fd/byte count) via libssl uprobes — OFF by default (#55)")
	tlsBytes := flag.Int("tls-bytes", 0, "Also capture up to N bytes of PLAINTEXT per TLS call (implies --tls; 0=metadata only, max 4096). Sensitive: may include credentials/PII")
	pprofAddr := flag.String("pprof", "", "Dev: serve net/http/pprof on this addr (e.g. localhost:6060) for profiling ptop itself")
	showVer := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVer {
		fmt.Printf("ptop %s (commit %s, built %s)\n", version, commit, buildDate)
		os.Exit(0)
	}

	if *pid <= 0 {
		if *pid == 0 {
			fmt.Fprintln(os.Stderr, "error: --pid is required")
		} else {
			fmt.Fprintf(os.Stderr, "error: --pid %d is not a valid PID\n", *pid)
		}
		fmt.Fprintln(os.Stderr, "usage: ptop --pid <PID> [--fps 5] [--no-ebpf] [--export]")
		fmt.Fprintln(os.Stderr, "       ptop --pid <PID> --serve unix:///run/ptop.sock")
		fmt.Fprintln(os.Stderr, "       ptop --version")
		os.Exit(1)
	}

	if err := checkPIDExists(*pid); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Profiling endpoint (dev tool, opt-in). Serves /debug/pprof for inspecting
	// ptop's own CPU/heap/goroutines — dogfood with `ptop --pid $(pgrep ptop)`.
	// It exposes process internals, so prefer a loopback addr.
	if *pprofAddr != "" {
		addr := *pprofAddr
		fmt.Fprintf(os.Stderr, "[ptop] pprof listening on http://%s/debug/pprof/\n", addr)
		go func() {
			srv := &http.Server{Addr: addr, ReadHeaderTimeout: 5 * time.Second}
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				fmt.Fprintf(os.Stderr, "[ptop] pprof server error: %v\n", err)
			}
		}()
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

	// TLS payload capture (#55) is opt-in. --tls-bytes implies --tls. Clamp the
	// per-call byte cap to [0, 4096] and warn loudly when plaintext is captured,
	// since it can include credentials/PII.
	tlsEnabled := *tls || *tlsBytes > 0
	tlsCap := *tlsBytes
	if tlsCap < 0 {
		tlsCap = 0
	}
	if tlsCap > 4096 {
		fmt.Fprintf(os.Stderr, "[ptop] --tls-bytes %d clamped to 4096 (per-call cap)\n", *tlsBytes)
		tlsCap = 4096
	}
	if tlsEnabled && tlsCap > 0 {
		fmt.Fprintf(os.Stderr, "[ptop] ⚠ TLS plaintext capture ON (--tls-bytes %d): events carry decrypted\n", tlsCap)
		fmt.Fprintln(os.Stderr, "       payload bytes (credentials/PII). Keep the stream/export private.")
	}

	// Headless mode: serve the collector stream over gRPC instead of the TUI.
	if *serveAddr != "" {
		runServe(*serveAddr, *pid, *noEBPF, *export, tlsEnabled, tlsCap)
		return
	}

	cfg := tui.Config{
		PID:         *pid,
		FPS:         *fps,
		NoEBPF:      *noEBPF,
		Export:      *export,
		TLS:         tlsEnabled,
		TLSMaxBytes: tlsCap,
	}

	// Resolve the terminal color profile once and pin it. Otherwise lipgloss
	// re-resolves it lazily and each styled segment re-probes the profile when
	// converting the 24-bit palette to ANSI — wasteful on the render hot path.
	lipgloss.SetColorProfile(lipgloss.ColorProfile())

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

// checkPIDExists verifies the target process exists before anything starts.
// Without this, a nonexistent PID silently fails every collector and the TUI
// falls back to simulated data — plausible-looking numbers for a process that
// isn't there (#90). kill(pid, 0) delivers no signal, it only performs the
// existence/permission check; same semantics on Linux and macOS.
func checkPIDExists(pid int) error {
	err := syscall.Kill(pid, 0)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, syscall.ESRCH):
		return fmt.Errorf("process %d does not exist", pid)
	case errors.Is(err, syscall.EPERM):
		// EPERM means the process exists but belongs to another user.
		// Collectors will degrade (macOS libproc needs same-euid), so warn
		// rather than fail: partial data for a real process is still useful.
		fmt.Fprintf(os.Stderr, "[ptop] warning: process %d is owned by another user — data may be limited or unavailable\n", pid)
		return nil
	default:
		return fmt.Errorf("cannot check process %d: %w", pid, err)
	}
}

// runServe builds the collector Set and streams it over gRPC until SIGINT/
// SIGTERM. The Set's lifecycle is owned here: serve.Run only stops the server,
// so we stop the collectors after it returns. With export, it also writes an
// event-level JSONL (distinct from the TUI's state-snapshot ptop-export-*.jsonl).
func runServe(addr string, pid int, noEBPF, export, tlsEnabled bool, tlsBytes int) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var opts serve.Options
	if export {
		opts.JSONLPath = fmt.Sprintf("ptop-events-%s.jsonl", time.Now().Format("20060102-150405"))
	}

	set := collector.NewSet(collector.SetConfig{
		PID: pid, NoEBPF: noEBPF, TLS: tlsEnabled, TLSMaxBytes: tlsBytes,
	})
	defer set.Stop()

	// The heap collector owns the stack tracer + symbolizer, so it backs stack
	// references + the ResolveStack RPC. Pass an untyped nil when it never
	// started (avoid a non-nil interface wrapping a nil pointer).
	var resolver serve.StackResolver
	if set.HeapEBPF != nil {
		resolver = set.HeapEBPF
	}

	if err := serve.Run(ctx, addr, pid, set.Collectors(), resolver, opts); err != nil {
		set.Stop() // os.Exit skips the defer
		fmt.Fprintf(os.Stderr, "fatal error: %v\n", err)
		os.Exit(1)
	}
}
