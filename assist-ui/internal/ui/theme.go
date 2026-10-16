package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

type duckJumpTheme struct{}

func newDuckJumpTheme() fyne.Theme {
	return &duckJumpTheme{}
}

func (d *duckJumpTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return color.NRGBA{R: 15, G: 23, B: 42, A: 255} // #0f172a slate-900
	case theme.ColorNameInputBackground:
		return color.NRGBA{R: 30, G: 41, B: 59, A: 255} // #1e293b slate-800
	case theme.ColorNameOverlayBackground:
		return color.NRGBA{R: 30, G: 41, B: 59, A: 240}
	case theme.ColorNameButton:
		return color.NRGBA{R: 51, G: 65, B: 85, A: 255} // #334155 slate-700
	case theme.ColorNamePrimary:
		return color.NRGBA{R: 250, G: 204, B: 21, A: 255} // #facc15 duck yellow
	case theme.ColorNameForeground:
		return color.NRGBA{R: 248, G: 250, B: 252, A: 255} // #f8fafc slate-50
	case theme.ColorNamePlaceHolder:
		return color.NRGBA{R: 148, G: 163, B: 184, A: 255} // #94a3b8 slate-400
	case theme.ColorNameError:
		return color.NRGBA{R: 239, G: 68, B: 68, A: 255} // #ef4444 red-500
	case theme.ColorNameSuccess:
		return color.NRGBA{R: 34, G: 197, B: 94, A: 255} // #22c55e green-500
	case theme.ColorNameWarning:
		return color.NRGBA{R: 245, G: 158, B: 11, A: 255} // #f59e0b amber-500
	default:
		return theme.DefaultTheme().Color(name, theme.VariantDark)
	}
}

func (d *duckJumpTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (d *duckJumpTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (d *duckJumpTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNameText:
		return 14
	case theme.SizeNameHeadingText:
		return 22
	case theme.SizeNameSubHeadingText:
		return 16
	case theme.SizeNamePadding:
		return 10
	case theme.SizeNameInputRadius:
		return 8
	default:
		return theme.DefaultTheme().Size(name)
	}
}
