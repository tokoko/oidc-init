package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tokoko/oidc-init/internal/storage"
)

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Manage stored OIDC tokens",
}

var tokenListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all stored tokens",
	Run: func(cmd *cobra.Command, args []string) {
		keys, err := storage.ListKeys()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if len(keys) == 0 {
			fmt.Println("No stored tokens found.")
			return
		}
		for _, key := range keys {
			expired, _ := storage.IsExpired(key)
			status := "valid"
			if expired {
				status = "expired"
			}
			data, err := storage.GetMetadata(key)
			if err != nil {
				fmt.Printf("  %s  [error reading metadata]\n", key)
				continue
			}
			fmt.Printf("  %-30s  %-8s  expires: %s  scope: %s\n", key, status, data.ExpiresAt, data.Scope)
		}
	},
}

var tokenShowCmd = &cobra.Command{
	Use:   "show STORAGE_KEY",
	Short: "Show token details",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		key := args[0]
		data, err := storage.GetMetadata(key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		expired, _ := storage.IsExpired(key)
		status := "valid"
		if expired {
			status = "expired"
		}
		fmt.Printf("Storage Key:    %s\n", key)
		fmt.Printf("Status:         %s\n", status)
		fmt.Printf("Token Type:     %s\n", data.TokenType)
		fmt.Printf("Issued At:      %s\n", data.IssuedAt)
		fmt.Printf("Expires At:     %s\n", data.ExpiresAt)
		fmt.Printf("Scope:          %s\n", data.Scope)
		if data.RefreshToken != "" {
			fmt.Printf("Refresh Token:  present\n")
		}
		if data.IDToken != "" {
			fmt.Printf("ID Token:       present\n")
		}
	},
}

var tokenGetCmd = &cobra.Command{
	Use:   "get [STORAGE_KEY]",
	Short: "Retrieve stored tokens",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		key := resolveTokenKey(args)
		if key == "" {
			return
		}

		accessTokenOnly, _ := cmd.Flags().GetBool("access-token-only")
		data, err := storage.GetTokens(key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if accessTokenOnly {
			fmt.Print(data.AccessToken)
			return
		}

		out, _ := json.MarshalIndent(data, "", "  ")
		fmt.Println(string(out))
	},
}

var tokenPathCmd = &cobra.Command{
	Use:   "path [STORAGE_KEY]",
	Short: "Get path to file containing access token",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		key := resolveTokenKey(args)
		if key == "" {
			return
		}

		p, err := storage.GetTokenFilePath(key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(p)
	},
}

var tokenDeleteCmd = &cobra.Command{
	Use:   "delete STORAGE_KEY",
	Short: "Delete stored tokens",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		key := args[0]
		yes, _ := cmd.Flags().GetBool("yes")
		if !yes {
			if !confirm(fmt.Sprintf("Delete tokens for %q?", key)) {
				fmt.Println("Cancelled.")
				return
			}
		}
		if err := storage.DeleteTokens(key); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Tokens for %q deleted.\n", key)
	},
}

var tokenPurgeCmd = &cobra.Command{
	Use:   "purge",
	Short: "Delete all stored tokens",
	Run: func(cmd *cobra.Command, args []string) {
		yes, _ := cmd.Flags().GetBool("yes")
		if !yes {
			if !confirm("Delete ALL stored tokens?") {
				fmt.Println("Cancelled.")
				return
			}
		}
		if err := storage.PurgeAll(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("All tokens deleted.")
	},
}

func init() {
	tokenGetCmd.Flags().Bool("access-token-only", false, "Output only the access token")

	tokenDeleteCmd.Flags().BoolP("yes", "y", false, "Skip confirmation")

	tokenPurgeCmd.Flags().BoolP("yes", "y", false, "Skip confirmation")

	tokenCmd.AddCommand(tokenListCmd)
	tokenCmd.AddCommand(tokenShowCmd)
	tokenCmd.AddCommand(tokenGetCmd)
	tokenCmd.AddCommand(tokenPathCmd)
	tokenCmd.AddCommand(tokenDeleteCmd)
	tokenCmd.AddCommand(tokenPurgeCmd)

	rootCmd.AddCommand(tokenCmd)
}

// resolveTokenKey returns the storage key from args or the single available key.
func resolveTokenKey(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	keys, err := storage.ListKeys()
	if err != nil || len(keys) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no stored tokens found")
		os.Exit(1)
	}
	if len(keys) == 1 {
		return keys[0]
	}
	fmt.Fprintln(os.Stderr, "Error: multiple tokens found, please specify a storage key:")
	for _, k := range keys {
		fmt.Fprintf(os.Stderr, "  %s\n", k)
	}
	os.Exit(1)
	return ""
}

// confirm prompts the user for y/n confirmation.
func confirm(prompt string) bool {
	fmt.Printf("%s [y/N] ", prompt)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}
