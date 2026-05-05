package tui

import "github.com/charmbracelet/lipgloss"

// Paleta — espelha exatamente o mockup React (assets/mockup.jsx)
var (
	ColorBG     = lipgloss.Color("#0e1014")
	ColorPanel  = lipgloss.Color("#13161c")
	ColorBorder = lipgloss.Color("#2a2d35")
	ColorDim    = lipgloss.Color("#3a3d45")
	ColorMuted  = lipgloss.Color("#5a5f72")
	ColorText   = lipgloss.Color("#c8ccd8")
	ColorBright = lipgloss.Color("#e8ecf5")
	ColorGreen  = lipgloss.Color("#4ade80")
	ColorCyan   = lipgloss.Color("#22d3ee")
	ColorAmber  = lipgloss.Color("#fbbf24")
	ColorRed    = lipgloss.Color("#f87171")
	ColorBlue   = lipgloss.Color("#60a5fa")
	ColorPurple = lipgloss.Color("#a78bfa")
	ColorPink   = lipgloss.Color("#f472b6")
	ColorOrange = lipgloss.Color("#fb923c")
	ColorTeal   = lipgloss.Color("#2dd4bf")
)

// Estilos de painel
var (
	PanelStyle = lipgloss.NewStyle().
			Background(ColorPanel).
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(ColorBorder)

	PanelTitleStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#0d1017")).
			Foreground(ColorCyan).
			PaddingLeft(1).PaddingRight(1).
			Bold(false)

	HeaderStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#0a0d11")).
			Foreground(ColorText).
			PaddingLeft(1).PaddingRight(1)

	StatusBarStyle = lipgloss.NewStyle().
			Background(lipgloss.Color("#0a0d11")).
			Foreground(ColorDim).
			PaddingLeft(1).PaddingRight(1)
)

// Estilos de texto semânticos
var (
	BrightStyle = lipgloss.NewStyle().Foreground(ColorBright)
	MutedStyle  = lipgloss.NewStyle().Foreground(ColorMuted)
	DimStyle    = lipgloss.NewStyle().Foreground(ColorDim)
	GreenStyle  = lipgloss.NewStyle().Foreground(ColorGreen)
	CyanStyle   = lipgloss.NewStyle().Foreground(ColorCyan)
	AmberStyle  = lipgloss.NewStyle().Foreground(ColorAmber)
	RedStyle    = lipgloss.NewStyle().Foreground(ColorRed)
	BlueStyle   = lipgloss.NewStyle().Foreground(ColorBlue)
	PurpleStyle = lipgloss.NewStyle().Foreground(ColorPurple)
	OrangeStyle = lipgloss.NewStyle().Foreground(ColorOrange)
	TealStyle   = lipgloss.NewStyle().Foreground(ColorTeal)
)

// Badge: pequeno label colorido inline (ex: "PID 18423", "RUNNING").
// Single-line por design — usado em headers e tabs onde altura > 1 quebra layout.
func Badge(label string, color lipgloss.Color) string {
	return lipgloss.NewStyle().
		Foreground(color).
		Background(lipgloss.Color("#1a1d24")).
		PaddingLeft(1).PaddingRight(1).
		Bold(true).
		Render(label)
}

// CategoryColor retorna a cor da categoria de evento no timeline
func CategoryColor(cat string) lipgloss.Color {
	switch cat {
	case "syscall":
		return ColorCyan
	case "net":
		return ColorBlue
	case "mem":
		return ColorPurple
	case "cpu":
		return ColorGreen
	case "lock":
		return ColorAmber
	case "io":
		return ColorOrange
	case "fd":
		return ColorTeal
	default:
		return ColorMuted
	}
}

// CategoryLabel retorna o label curto da categoria (3 chars)
func CategoryLabel(cat string) string {
	switch cat {
	case "syscall":
		return "SYS"
	case "net":
		return "NET"
	case "mem":
		return "MEM"
	case "cpu":
		return "CPU"
	case "lock":
		return "LCK"
	case "io":
		return "I/O"
	case "fd":
		return "FD "
	default:
		return "???"
	}
}

// FDTypeColor retorna a cor do tipo de FD
func FDTypeColor(fdType string) lipgloss.Color {
	switch fdType {
	case "file":
		return ColorCyan
	case "socket":
		return ColorBlue
	case "pipe":
		return ColorPurple
	case "epoll":
		return ColorAmber
	case "timer":
		return ColorGreen
	default:
		return ColorMuted
	}
}

// FDTypeIcon retorna o ícone Unicode do tipo de FD
func FDTypeIcon(fdType string) string {
	switch fdType {
	case "file":
		return "f"
	case "socket":
		return "s"
	case "pipe":
		return "p"
	case "epoll":
		return "e"
	case "timer":
		return "t"
	default:
		return "?"
	}
}
