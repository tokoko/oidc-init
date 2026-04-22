//go:build gui

package gui

import (
	_ "embed"

	"fyne.io/fyne/v2"
)

//go:embed logo.svg
var logoSVG []byte

var logoResource = fyne.NewStaticResource("oidc-init-logo.svg", logoSVG)
