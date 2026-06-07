//go:build darwin

package collector

// See source_linux.go. On macOS the rich eBPF tier doesn't exist; libproc is
// the only public path, so both labels collapse to "libproc".
const (
	SourceProc        = "libproc"
	SourceNetworkRich = "libproc"
)
