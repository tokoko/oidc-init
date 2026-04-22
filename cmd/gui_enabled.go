//go:build gui

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/tokoko/oidc-init/internal/gui"
)

var guiCmd = &cobra.Command{
	Use:   "gui",
	Short: "Launch the desktop GUI",
	Run: func(cmd *cobra.Command, args []string) {
		gui.Run()
	},
}

func init() {
	rootCmd.AddCommand(guiCmd)
	// With the GUI built in, running the binary with no subcommand
	// launches the window — this is what makes double-clicking the
	// .exe on Windows open the GUI directly.
	rootCmd.Run = guiCmd.Run
}
