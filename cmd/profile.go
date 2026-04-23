package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tokoko/oidc-init/internal/profiles"
)

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage OIDC provider profiles",
}

var profileAddCmd = &cobra.Command{
	Use:   "add NAME",
	Short: "Add a new profile",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		name := args[0]
		endpoint, _ := cmd.Flags().GetString("endpoint")
		realm, _ := cmd.Flags().GetString("realm")
		clientID, _ := cmd.Flags().GetString("client-id")
		clientSecret, _ := cmd.Flags().GetString("client-secret")
		scope, _ := cmd.Flags().GetString("scope")
		flow, _ := cmd.Flags().GetString("flow")
		protocol, _ := cmd.Flags().GetString("protocol")
		noVerify, _ := cmd.Flags().GetBool("no-verify")
		overwrite, _ := cmd.Flags().GetBool("overwrite")
		setDefault, _ := cmd.Flags().GetBool("set-default")

		mgr, err := profiles.NewManager()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		p := &profiles.Profile{
			Endpoint:     endpoint,
			Realm:        realm,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scope:        scope,
			Protocol:     protocol,
			Flow:         flow,
			Verify:       !noVerify,
		}

		if err := mgr.Add(name, p, overwrite); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Profile %q added.\n", name)

		if setDefault {
			if err := mgr.SetDefault(name); err != nil {
				fmt.Fprintf(os.Stderr, "Error setting default: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Profile %q set as default.\n", name)
		}
	},
}

var profileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all saved profiles",
	Run: func(cmd *cobra.Command, args []string) {
		mgr, err := profiles.NewManager()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		names, err := mgr.List()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if len(names) == 0 {
			fmt.Println("No profiles found.")
			return
		}

		def, _ := mgr.GetDefault()

		for _, name := range names {
			marker := "  "
			if name == def {
				marker = "* "
			}
			p, err := mgr.Get(name)
			if err != nil {
				fmt.Printf("%s%s  [error reading profile]\n", marker, name)
				continue
			}
			fmt.Printf("%s%-20s  endpoint: %s  realm: %s  client: %s\n", marker, name, p.Endpoint, p.Realm, p.ClientID)
		}
	},
}

var profileShowCmd = &cobra.Command{
	Use:   "show NAME",
	Short: "Show details of a profile",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		name := args[0]
		mgr, err := profiles.NewManager()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		p, err := mgr.Get(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		def, _ := mgr.GetDefault()

		fmt.Printf("Name:           %s\n", name)
		if name == def {
			fmt.Printf("Default:        yes\n")
		}
		fmt.Printf("Endpoint:       %s\n", p.Endpoint)
		fmt.Printf("Realm:          %s\n", p.Realm)
		fmt.Printf("Client ID:      %s\n", p.ClientID)
		if p.ClientSecret != "" {
			fmt.Printf("Client Secret:  ****\n")
		}
		fmt.Printf("Scope:          %s\n", p.Scope)
		fmt.Printf("Protocol:       %s\n", p.Protocol)
		fmt.Printf("Flow:           %s\n", p.Flow)
		fmt.Printf("SSL Verify:     %v\n", p.Verify)
	},
}

var profileDeleteCmd = &cobra.Command{
	Use:   "delete NAME",
	Short: "Delete a profile",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		name := args[0]
		yes, _ := cmd.Flags().GetBool("yes")
		if !yes {
			if !confirm(fmt.Sprintf("Delete profile %q?", name)) {
				fmt.Println("Cancelled.")
				return
			}
		}

		mgr, err := profiles.NewManager()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if err := mgr.Delete(name); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Profile %q deleted.\n", name)
	},
}

var profileSetDefaultCmd = &cobra.Command{
	Use:   "set-default NAME",
	Short: "Set a profile as the default",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		name := args[0]
		mgr, err := profiles.NewManager()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if err := mgr.SetDefault(name); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Default profile set to %q.\n", name)
	},
}

var profileImportCmd = &cobra.Command{
	Use:   "import SOURCE",
	Short: "Import profiles from a JSON file or URL",
	Long: `Import one or more profiles from a JSON document.

SOURCE may be a local file path or an http(s):// URL. The document is a JSON
object mapping profile name to a Profile (same shape as ~/.oidc/profiles.json).
Keys beginning with "_" are reserved metadata and are ignored.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		source := args[0]
		noOverwrite, _ := cmd.Flags().GetBool("no-overwrite")
		overwrite := !noOverwrite

		reader, err := openImportSource(source)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		defer reader.Close()

		mgr, err := profiles.NewManager()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		result, err := mgr.Import(reader, overwrite)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		for _, n := range result.Added {
			fmt.Printf("✓ %s\n", n)
		}
		for _, n := range result.Skipped {
			fmt.Printf("- %s (already exists)\n", n)
		}
		for n, msg := range result.Errors {
			fmt.Fprintf(os.Stderr, "✗ %s: %s\n", n, msg)
		}
		fmt.Printf("\nImported %d, skipped %d, errors %d.\n",
			len(result.Added), len(result.Skipped), len(result.Errors))

		if len(result.Errors) > 0 {
			os.Exit(1)
		}
	},
}

// openImportSource returns a ReadCloser for either a local file or an http(s) URL.
func openImportSource(source string) (io.ReadCloser, error) {
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(source)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch %s: %w", source, err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("fetch %s returned HTTP %d", source, resp.StatusCode)
		}
		return resp.Body, nil
	}
	f, err := os.Open(source)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", source, err)
	}
	return f, nil
}

var profileUnsetDefaultCmd = &cobra.Command{
	Use:   "unset-default",
	Short: "Unset the default profile",
	Run: func(cmd *cobra.Command, args []string) {
		mgr, err := profiles.NewManager()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if err := mgr.UnsetDefault(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Default profile unset.")
	},
}

func init() {
	profileAddCmd.Flags().String("endpoint", "", "OIDC provider endpoint")
	profileAddCmd.Flags().String("realm", "", "Realm or tenant name")
	profileAddCmd.Flags().String("client-id", "", "OAuth2/OIDC client ID")
	profileAddCmd.Flags().String("client-secret", "", "Client secret")
	profileAddCmd.Flags().String("scope", "openid profile email", "Space-separated scopes")
	profileAddCmd.Flags().String("flow", "device", "Authentication flow")
	profileAddCmd.Flags().String("protocol", "https", "Protocol (http or https)")
	profileAddCmd.Flags().Bool("no-verify", false, "Disable SSL certificate verification")
	profileAddCmd.Flags().Bool("overwrite", false, "Overwrite if profile exists")
	profileAddCmd.Flags().Bool("set-default", false, "Set as default profile")

	profileDeleteCmd.Flags().BoolP("yes", "y", false, "Skip confirmation")

	profileImportCmd.Flags().Bool("no-overwrite", false, "Skip profiles that already exist instead of replacing them")

	profileCmd.AddCommand(profileAddCmd)
	profileCmd.AddCommand(profileListCmd)
	profileCmd.AddCommand(profileShowCmd)
	profileCmd.AddCommand(profileDeleteCmd)
	profileCmd.AddCommand(profileSetDefaultCmd)
	profileCmd.AddCommand(profileUnsetDefaultCmd)
	profileCmd.AddCommand(profileImportCmd)

	rootCmd.AddCommand(profileCmd)
}
