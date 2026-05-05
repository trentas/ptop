package collector

import "testing"

// TestDetectClkTck — em qualquer sistema POSIX (Linux/macOS) `getconf CLK_TCK`
// retorna um valor sensato. Em sistemas onde o comando não existe, o fallback
// é 100. Verificamos que retorna >0 e está num range razoável.
func TestDetectClkTck(t *testing.T) {
	v := detectClkTck()
	if v <= 0 {
		t.Fatalf("clkTck deve ser positivo, got %v", v)
	}
	// Valores conhecidos: 100 (x86 Ubuntu), 250 (ARM Ubuntu/RHEL), 1000 (Fedora ARM)
	if v < 50 || v > 10000 {
		t.Errorf("clkTck %v fora de range razoável (50..10000)", v)
	}
}
