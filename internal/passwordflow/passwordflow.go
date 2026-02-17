package passwordflow

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"golang.org/x/term"
)

// Config holds parameters for the Resource Owner Password Credentials flow.
type Config struct {
	TokenEndpoint string
	ClientID      string
	ClientSecret  string
	Username      string
	Scope         string
	HTTPClient    *http.Client
}

// TokenResponse is the successful token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// PromptPassword reads a password from the terminal without echoing.
func PromptPassword() (string, error) {
	fmt.Fprint(os.Stderr, "Password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}
	return string(password), nil
}

// RequestToken exchanges username and password for tokens using the Resource
// Owner Password Credentials grant (RFC 6749 §4.3).
func RequestToken(ctx context.Context, cfg *Config, password string) (*TokenResponse, error) {
	form := url.Values{
		"grant_type": {"password"},
		"username":   {cfg.Username},
		"password":   {password},
		"client_id":  {cfg.ClientID},
	}
	if cfg.ClientSecret != "" {
		form.Set("client_secret", cfg.ClientSecret)
	}
	if cfg.Scope != "" {
		form.Set("scope", cfg.Scope)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp tokenErrorResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			if errResp.ErrorDescription != "" {
				return nil, fmt.Errorf("authentication failed: %s (%s)", errResp.ErrorDescription, errResp.Error)
			}
			return nil, fmt.Errorf("authentication failed: %s", errResp.Error)
		}
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tr, nil
}
