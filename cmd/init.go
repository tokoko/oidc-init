package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/tokoko/oidc-init/internal/auth"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize OIDC authentication and obtain tokens",
	Run: func(cmd *cobra.Command, args []string) {
		profile, _ := cmd.Flags().GetString("profile")
		endpoint, _ := cmd.Flags().GetString("endpoint")
		realm, _ := cmd.Flags().GetString("realm")
		clientID, _ := cmd.Flags().GetString("client-id")
		clientSecret, _ := cmd.Flags().GetString("client-secret")
		scope, _ := cmd.Flags().GetString("scope")
		flow, _ := cmd.Flags().GetString("flow")
		protocol, _ := cmd.Flags().GetString("protocol")
		timeout, _ := cmd.Flags().GetInt("timeout")
		noVerify, _ := cmd.Flags().GetBool("no-verify")
		saveProfile, _ := cmd.Flags().GetString("save-profile")
		username, _ := cmd.Flags().GetString("username")

		// Don't pass default flag values as explicit overrides when a profile
		// is in play — only pass values the user actually set on the command line.
		if !cmd.Flags().Changed("scope") {
			scope = ""
		}
		if !cmd.Flags().Changed("flow") {
			flow = ""
		}
		if !cmd.Flags().Changed("protocol") {
			protocol = ""
		}

		opts := &auth.Options{
			Profile:      profile,
			Endpoint:     endpoint,
			Realm:        realm,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scope:        scope,
			Flow:         flow,
			Protocol:     protocol,
			NoVerify:     noVerify,
			Timeout:      timeout,
			SaveProfile:  saveProfile,
			Username:     username,
		}

		_, err := auth.RunInit(context.Background(), opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	initCmd.Flags().String("profile", "", "Use a saved profile")
	initCmd.Flags().String("endpoint", "", "OIDC provider endpoint")
	initCmd.Flags().String("realm", "", "Realm or tenant name")
	initCmd.Flags().String("client-id", "", "OAuth2/OIDC client ID")
	initCmd.Flags().String("client-secret", "", "Client secret")
	initCmd.Flags().String("scope", "openid profile email", "Space-separated scopes")
	initCmd.Flags().String("flow", "device", "Authentication flow to use")
	initCmd.Flags().String("protocol", "https", "Protocol (http or https)")
	initCmd.Flags().Int("timeout", 0, "Custom timeout in seconds")
	initCmd.Flags().Bool("no-verify", false, "Disable SSL certificate verification")
	initCmd.Flags().String("save-profile", "", "Save configuration as a profile")
	initCmd.Flags().String("username", "", "Username for password flow")

	rootCmd.AddCommand(initCmd)
}
