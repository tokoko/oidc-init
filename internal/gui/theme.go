//go:build gui

package gui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

type appTheme struct{}

var _ fyne.Theme = (*appTheme)(nil)

// Palette: forced dark-gray theme with white text and a violet accent.
// We ignore the system variant and always return these values.
var (
	bgColor       = color.NRGBA{R: 0x2a, G: 0x2d, B: 0x34, A: 0xff}
	cardColor     = color.NRGBA{R: 0x34, G: 0x37, B: 0x3f, A: 0xff}
	fg            = color.NRGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff}
	muted         = color.NRGBA{R: 0xb4, G: 0xb7, B: 0xbe, A: 0xff}
	border        = color.NRGBA{R: 0x44, G: 0x47, B: 0x4f, A: 0xff}
	hover         = color.NRGBA{R: 0x3d, G: 0x40, B: 0x49, A: 0xff}
	accent        = color.NRGBA{R: 0x8b, G: 0x5c, B: 0xf6, A: 0xff}
	accentTextCol = color.NRGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff}
)

func accentColor(_ fyne.App) color.Color { return accent }
func fgColor(_ fyne.App) color.Color     { return fg }
func mutedColor(_ fyne.App) color.Color  { return muted }

func (appTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return bgColor
	case theme.ColorNameForeground:
		return fg
	case theme.ColorNameForegroundOnPrimary:
		return accentTextCol
	case theme.ColorNamePrimary:
		return accent
	case theme.ColorNameButton, theme.ColorNameInputBackground,
		theme.ColorNameOverlayBackground, theme.ColorNameMenuBackground:
		return cardColor
	case theme.ColorNameInputBorder, theme.ColorNameSeparator:
		return border
	case theme.ColorNamePlaceHolder, theme.ColorNameDisabled:
		return muted
	case theme.ColorNameHover:
		return hover
	case theme.ColorNameShadow:
		return color.NRGBA{R: 0x00, G: 0x00, B: 0x00, A: 0x80}
	}
	return theme.DefaultTheme().Color(name, theme.VariantDark)
}

func (appTheme) Font(s fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(s)
}

func (appTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (appTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNameText:
		return 13
	case theme.SizeNameHeadingText:
		return 22
	case theme.SizeNameSubHeadingText:
		return 16
	case theme.SizeNamePadding:
		return 6
	case theme.SizeNameInnerPadding:
		return 10
	case theme.SizeNameInputRadius, theme.SizeNameSelectionRadius:
		return 6
	case theme.SizeNameScrollBar:
		return 10
	}
	return theme.DefaultTheme().Size(name)
}
