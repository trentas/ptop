package tui

import "github.com/charmbracelet/lipgloss"

// Palette — exactly mirrors the React mockup (assets/mockup.jsx)
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

// Panel styles
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

// Semantic text styles.
//
// IMPORTANT: all have an explicit Background(ColorPanel). Without it, cells
// rendered inside panels get the terminal's default background
// (which is Ubuntu's mauve, or whatever the user's theme color is) — leaking
// through gaps between colored segments.
//
// Header/tabbar/statusbar use inline styles with their own backgrounds
// and DO NOT consume these; see header.go, tabbar.go, statusbar.go.
var (
	BrightStyle = lipgloss.NewStyle().Foreground(ColorBright).Background(ColorPanel)
	MutedStyle  = lipgloss.NewStyle().Foreground(ColorMuted).Background(ColorPanel)
	DimStyle    = lipgloss.NewStyle().Foreground(ColorDim).Background(ColorPanel)
	GreenStyle  = lipgloss.NewStyle().Foreground(ColorGreen).Background(ColorPanel)
	CyanStyle   = lipgloss.NewStyle().Foreground(ColorCyan).Background(ColorPanel)
	AmberStyle  = lipgloss.NewStyle().Foreground(ColorAmber).Background(ColorPanel)
	RedStyle    = lipgloss.NewStyle().Foreground(ColorRed).Background(ColorPanel)
	BlueStyle   = lipgloss.NewStyle().Foreground(ColorBlue).Background(ColorPanel)
	PurpleStyle = lipgloss.NewStyle().Foreground(ColorPurple).Background(ColorPanel)
	OrangeStyle = lipgloss.NewStyle().Foreground(ColorOrange).Background(ColorPanel)
	TealStyle   = lipgloss.NewStyle().Foreground(ColorTeal).Background(ColorPanel)
)

// PanelStyleBase returns a base style with ColorPanel as background.
// Use to build inline styles inside panels:
//
//	name := PanelStyleBase().Foreground(c).Width(nameW).Render(s)
//
// Just sugar for `lipgloss.NewStyle().Background(ColorPanel)` but makes
// the intent clear.
func PanelStyleBase() lipgloss.Style {
	return lipgloss.NewStyle().Background(ColorPanel)
}

// Badge: small inline colored label (e.g. "PID 18423", "RUNNING").
// Single-line by design — used in headers and tabs where height > 1 breaks layout.
func Badge(label string, color lipgloss.Color) string {
	return lipgloss.NewStyle().
		Foreground(color).
		Background(lipgloss.Color("#1a1d24")).
		PaddingLeft(1).PaddingRight(1).
		Bold(true).
		Render(label)
}

// CategoryColor returns the color of the event category in the timeline
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
	case "sig":
		return ColorPink
	default:
		return ColorMuted
	}
}

// CategoryLabel returns the short category label (3 chars)
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
	case "sig":
		return "SIG"
	default:
		return "???"
	}
}

// FDTypeColor returns the color for the FD type
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

// FDTypeIcon returns the Unicode icon for the FD type
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
