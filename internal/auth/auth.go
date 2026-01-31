package auth

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	"github.com/tokoko/oidc-init/internal/deviceflow"
	"github.com/tokoko/oidc-init/internal/profiles"
	"github.com/tokoko/oidc-init/internal/storage"
)

// Options holds all parameters for the init flow, combining CLI flags with
// profile values.
type Options struct {
	Profile     string
	Endpoint    string
	Realm       string
	ClientID    string
	ClientSecret string
	Scope       string
	Flow        string
	Protocol    string
	NoVerify    bool
	Timeout     int
	SaveProfile string
}

// Result is returned after a successful init.
type Result struct {
	StorageKey string
	Tokens     *storage.TokenData
}

// RunInit orchestrates the OIDC init flow: loads a profile (if specified),
// merges with explicit flags, validates, runs the device flow, and stores
// tokens.
func RunInit(ctx context.Context, opts *Options) (*Result, error) {
	// Resolve profile configuration.
	if err := resolveProfile(opts); err != nil {
		return nil, err
	}

	// Apply defaults.
	if opts.Scope == "" {
		opts.Scope = "openid profile email"
	}
	if opts.Flow == "" {
		opts.Flow = "device"
	}
	if opts.Protocol == "" {
		opts.Protocol = "https"
	}

	// Validate required parameters.
	if opts.Endpoint == "" {
		return nil, fmt.Errorf("endpoint is required (use --endpoint or a profile)")
	}
	if opts.Realm == "" {
		return nil, fmt.Errorf("realm is required (use --realm or a profile)")
	}
	if opts.ClientID == "" {
		return nil, fmt.Errorf("client-id is required (use --client-id or a profile)")
	}
	if opts.Flow != "device" {
		return nil, fmt.Errorf("unsupported flow %q (only 'device' is supported)", opts.Flow)
	}

	tokenEndpoint := BuildTokenEndpoint(opts.Endpoint, opts.Realm, opts.Protocol)

	httpClient := &http.Client{}
	if opts.NoVerify {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		}
		fmt.Println("WARNING: SSL certificate verification is disabled")
	}

	cfg := &deviceflow.Config{
		TokenEndpoint: tokenEndpoint,
		ClientID:      opts.ClientID,
		ClientSecret:  opts.ClientSecret,
		Scope:         opts.Scope,
		Timeout:       opts.Timeout,
		HTTPClient:    httpClient,
	}

	// Step 1: Request device code.
	dar, err := deviceflow.RequestDeviceCode(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to start device flow: %w", err)
	}

	// Step 2: Display instructions.
	deviceflow.PrintUserInstructions(dar)

	// Step 3: Poll for token.
	tokenResp, err := deviceflow.PollForToken(ctx, cfg, dar.DeviceCode, dar.ExpiresIn, dar.Interval)
	if err != nil {
		return nil, err
	}

	fmt.Println("Authentication successful!")

	// Step 4: Save tokens.
	storageKey := storage.GenerateStorageKey(opts.Endpoint, opts.Realm, opts.ClientID, opts.Profile)
	storageResp := &storage.TokenResponse{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		RefreshToken: tokenResp.RefreshToken,
		Scope:        tokenResp.Scope,
		IDToken:      tokenResp.IDToken,
	}
	if err := storage.SaveTokens(storageKey, storageResp); err != nil {
		return nil, fmt.Errorf("failed to save tokens: %w", err)
	}

	fmt.Printf("Tokens saved (key: %s)\n", storageKey)

	// Step 5: Optionally save profile.
	if opts.SaveProfile != "" {
		if err := saveProfile(opts); err != nil {
			return nil, fmt.Errorf("failed to save profile: %w", err)
		}
		fmt.Printf("Profile %q saved\n", opts.SaveProfile)
	}

	tokens, _ := storage.GetTokens(storageKey)
	return &Result{StorageKey: storageKey, Tokens: tokens}, nil
}

// BuildTokenEndpoint constructs a Keycloak-style token endpoint URL.
func BuildTokenEndpoint(endpoint, realm, protocol string) string {
	var baseURL string
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		baseURL = strings.TrimRight(endpoint, "/")
	} else {
		baseURL = fmt.Sprintf("%s://%s", protocol, endpoint)
	}
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", baseURL, realm)
}

// resolveProfile loads a named profile (or the default) and fills in any
// unset fields in opts.
func resolveProfile(opts *Options) error {
	profileName := opts.Profile
	if profileName == "" {
		// Try default profile.
		mgr, err := profiles.NewManager()
		if err != nil {
			return nil // No profile dir yet, that's fine.
		}
		def, err := mgr.GetDefault()
		if err != nil || def == "" {
			return nil
		}
		profileName = def
		opts.Profile = def
	}

	mgr, err := profiles.NewManager()
	if err != nil {
		return err
	}
	p, err := mgr.Get(profileName)
	if err != nil {
		return err
	}

	// Merge profile values into opts, only for fields not already set by flags.
	if opts.Endpoint == "" {
		opts.Endpoint = p.Endpoint
	}
	if opts.Realm == "" {
		opts.Realm = p.Realm
	}
	if opts.ClientID == "" {
		opts.ClientID = p.ClientID
	}
	if opts.ClientSecret == "" {
		opts.ClientSecret = p.ClientSecret
	}
	if opts.Scope == "" {
		opts.Scope = p.Scope
	}
	if opts.Flow == "" {
		opts.Flow = p.Flow
	}
	if opts.Protocol == "" {
		opts.Protocol = p.Protocol
	}
	if !opts.NoVerify && !p.Verify {
		opts.NoVerify = true
	}

	return nil
}

// saveProfile saves the current options as a named profile.
func saveProfile(opts *Options) error {
	mgr, err := profiles.NewManager()
	if err != nil {
		return err
	}
	p := &profiles.Profile{
		Endpoint:     opts.Endpoint,
		Realm:        opts.Realm,
		ClientID:     opts.ClientID,
		ClientSecret: opts.ClientSecret,
		Scope:        opts.Scope,
		Protocol:     opts.Protocol,
		Flow:         opts.Flow,
		Verify:       !opts.NoVerify,
	}
	return mgr.Add(opts.SaveProfile, p, true)
}
