package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "oidc",
	Short: "CLI tool for obtaining and caching OIDC tokens",
	Long:  "oidc-init is a CLI tool for obtaining and caching OIDC tokens from external providers, similar to how kinit is used in Kerberos authentication.",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
