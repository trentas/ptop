package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Braille block characters para sparkline (8 níveis de altura por coluna).
// Cada rune representa um nível de preenchimento vertical: vazio → cheio.
var brailleRamp = []rune{
	' ', '⡀', '⡄', '⡆', '⡇', '⡏', '⡟', '⡿',
}

// Sparkline renderiza uma série de dados como gráfico braille colorido,
// auto-escalando pela maior valor da janela. ATENÇÃO: usar esta variante
// faz a escala mudar a cada tick — o que causa "tudo pulando" visual.
// Para escala fixa (CPU em 0-100, IO com decay) prefira SparklineWithMax.
func Sparkline(data []float64, width int, color lipgloss.Color) string {
	max := 0.0
	for _, v := range data {
		if v > max {
			max = v
		}
	}
	return SparklineWithMax(data, width, max, color)
}

// SparklineWithMax usa um máximo externo para normalizar a série.
// Passe maxScale=100 para CPU%, ou um máximo com decay lento para IO/contadores.
// maxScale<=0 cai num gráfico em branco com um piso visual.
func SparklineWithMax(data []float64, width int, maxScale float64, color lipgloss.Color) string {
	if width <= 0 {
		return ""
	}
	if len(data) == 0 || maxScale <= 0 {
		return lipgloss.NewStyle().Foreground(ColorDim).Render(strings.Repeat(string(brailleRamp[0]), width))
	}

	points := data
	if len(points) > width {
		points = points[len(points)-width:]
	}

	style := lipgloss.NewStyle().Foreground(color)
	dimStyle := lipgloss.NewStyle().Foreground(ColorDim)

	var sb strings.Builder

	// padding esquerdo quando ainda temos menos amostras do que largura disponível
	for i := 0; i < width-len(points); i++ {
		sb.WriteString(dimStyle.Render(string(brailleRamp[0])))
	}

	for _, v := range points {
		level := int((v / maxScale) * float64(len(brailleRamp)-1))
		if level < 0 {
			level = 0
		}
		if level >= len(brailleRamp) {
			level = len(brailleRamp) - 1
		}
		ch := brailleRamp[level]
		if level == 0 {
			sb.WriteString(dimStyle.Render(string(ch)))
		} else {
			sb.WriteString(style.Render(string(ch)))
		}
	}

	return sb.String()
}

// DualSparkline renderiza duas séries sobrepostas (ex: read/write).
// A série `a` usa `colorA`, a série `b` usa `colorB`.
// Retorna duas linhas separadas por \n.
func DualSparkline(a, b []float64, width int, colorA, colorB lipgloss.Color) string {
	return Sparkline(a, width, colorA) + "\n" + Sparkline(b, width, colorB)
}

// HorizontalBar renderiza uma barra horizontal proporcional.
//
//	value:   valor atual
//	max:     valor máximo (fixo — passe sempre o mesmo entre frames pra
//	         evitar barras pulando de tamanho a cada tick)
//	width:   largura total em colunas
//	color:   cor da parte preenchida
func HorizontalBar(value, max float64, width int, color lipgloss.Color) string {
	if width <= 0 {
		return ""
	}
	if max <= 0 {
		return lipgloss.NewStyle().Foreground(ColorDim).Render(strings.Repeat("░", width))
	}
	if value < 0 {
		value = 0
	}
	if value > max {
		value = max
	}
	filled := int((value / max) * float64(width))
	if filled > width {
		filled = width
	}
	full := strings.Repeat("█", filled)
	empty := strings.Repeat("░", width-filled)
	return lipgloss.NewStyle().Foreground(color).Render(full) +
		lipgloss.NewStyle().Foreground(ColorDim).Render(empty)
}
