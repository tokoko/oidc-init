//go:build !gui

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var guiCmd = &cobra.Command{
	Use:   "gui",
	Short: "Launch the desktop GUI (not included in this build)",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Fprintln(os.Stderr, "This build of oidc was compiled without GUI support.")
		fmt.Fprintln(os.Stderr, "Rebuild with: go build -tags gui  (or: pixi run build-gui)")
		os.Exit(1)
	},
}

func init() {
	rootCmd.AddCommand(guiCmd)
}
