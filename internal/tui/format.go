package tui

import "fmt"

// fmtBytes converte uma contagem em bytes para uma string compacta com unidade.
// Ex: 1024 → "1.0KB", 1500000 → "1.4MB".
func fmtBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1fGB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

// fmtBytesPerSec é igual a fmtBytes mas com sufixo "/s".
func fmtBytesPerSec(bps float64) string {
	if bps < 0 {
		bps = 0
	}
	b := uint64(bps)
	switch {
	case b >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

// fmtAgeMs converte uma idade em milissegundos numa string compacta.
// Ex: 12000 → "12s", 90000 → "1m", 4000000 → "1h".
func fmtAgeMs(ms int64) string {
	if ms < 0 {
		ms = 0
	}
	s := ms / 1000
	switch {
	case s >= 3600:
		return fmt.Sprintf("%dh", s/3600)
	case s >= 60:
		return fmt.Sprintf("%dm", s/60)
	default:
		return fmt.Sprintf("%ds", s)
	}
}
