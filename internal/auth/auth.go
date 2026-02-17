package auth

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	"github.com/tokoko/oidc-init/internal/deviceflow"
	"github.com/tokoko/oidc-init/internal/passwordflow"
	"github.com/tokoko/oidc-init/internal/profiles"
	"github.com/tokoko/oidc-init/internal/storage"
)

// Options holds all parameters for the init flow, combining CLI flags with
// profile values.
type Options struct {
	Profile      string
	Endpoint     string
	Realm        string
	ClientID     string
	ClientSecret string
	Scope        string
	Flow         string
	Protocol     string
	NoVerify     bool
	Timeout      int
	SaveProfile  string
	Username     string
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

	tokenEndpoint := BuildTokenEndpoint(opts.Endpoint, opts.Realm, opts.Protocol)

	httpClient := &http.Client{}
	if opts.NoVerify {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		}
		fmt.Println("WARNING: SSL certificate verification is disabled")
	}

	var (
		storageResp *storage.TokenResponse
		err         error
	)

	switch opts.Flow {
	case "device":
		storageResp, err = runDeviceFlow(ctx, opts, tokenEndpoint, httpClient)
	case "password":
		storageResp, err = runPasswordFlow(ctx, opts, tokenEndpoint, httpClient)
	default:
		return nil, fmt.Errorf("unsupported flow %q (supported: device, password)", opts.Flow)
	}
	if err != nil {
		return nil, err
	}

	fmt.Println("Authentication successful!")

	// Save tokens.
	storageKey := storage.GenerateStorageKey(opts.Endpoint, opts.Realm, opts.ClientID, opts.Profile)
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

func runDeviceFlow(ctx context.Context, opts *Options, tokenEndpoint string, httpClient *http.Client) (*storage.TokenResponse, error) {
	cfg := &deviceflow.Config{
		TokenEndpoint: tokenEndpoint,
		ClientID:      opts.ClientID,
		ClientSecret:  opts.ClientSecret,
		Scope:         opts.Scope,
		Timeout:       opts.Timeout,
		HTTPClient:    httpClient,
	}

	dar, err := deviceflow.RequestDeviceCode(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to start device flow: %w", err)
	}

	deviceflow.PrintUserInstructions(dar)

	tokenResp, err := deviceflow.PollForToken(ctx, cfg, dar.DeviceCode, dar.ExpiresIn, dar.Interval)
	if err != nil {
		return nil, err
	}

	return &storage.TokenResponse{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		RefreshToken: tokenResp.RefreshToken,
		Scope:        tokenResp.Scope,
		IDToken:      tokenResp.IDToken,
	}, nil
}

func runPasswordFlow(ctx context.Context, opts *Options, tokenEndpoint string, httpClient *http.Client) (*storage.TokenResponse, error) {
	if opts.Username == "" {
		return nil, fmt.Errorf("username is required for password flow (use --username)")
	}

	password, err := passwordflow.PromptPassword()
	if err != nil {
		return nil, err
	}

	cfg := &passwordflow.Config{
		TokenEndpoint: tokenEndpoint,
		ClientID:      opts.ClientID,
		ClientSecret:  opts.ClientSecret,
		Username:      opts.Username,
		Scope:         opts.Scope,
		HTTPClient:    httpClient,
	}

	tokenResp, err := passwordflow.RequestToken(ctx, cfg, password)
	if err != nil {
		return nil, err
	}

	return &storage.TokenResponse{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		RefreshToken: tokenResp.RefreshToken,
		Scope:        tokenResp.Scope,
		IDToken:      tokenResp.IDToken,
	}, nil
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
	if opts.Username == "" {
		opts.Username = p.Username
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
		Username:     opts.Username,
	}
	return mgr.Add(opts.SaveProfile, p, true)
}
