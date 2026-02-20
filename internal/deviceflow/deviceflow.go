package deviceflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Sentinel errors.
var (
	ErrTimeout = errors.New("device code expired")
	ErrDenied  = errors.New("authorization request was denied")
)

// ErrDeviceFlow wraps unexpected errors from the device flow.
type ErrDeviceFlow struct {
	Code    string
	Message string
}

func (e *ErrDeviceFlow) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("device flow error: %s (%s)", e.Message, e.Code)
	}
	return fmt.Sprintf("device flow error: %s", e.Code)
}

// Config holds parameters for the device authorization flow.
type Config struct {
	TokenEndpoint string
	ClientID      string
	ClientSecret  string
	Scope         string
	Timeout       int // seconds; 0 means use server default
	HTTPClient    *http.Client
}

// DeviceAuthResponse is the response from the device authorization endpoint.
type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
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

// deviceAuthEndpoint derives the device authorization endpoint from the token
// endpoint by replacing "/token" with "/auth/device" (Keycloak convention).
func deviceAuthEndpoint(tokenEndpoint string) string {
	return strings.Replace(tokenEndpoint, "/token", "/auth/device", 1)
}

// RequestDeviceCode initiates the device authorization request (RFC 8628).
func RequestDeviceCode(ctx context.Context, cfg *Config) (*DeviceAuthResponse, error) {
	endpoint := deviceAuthEndpoint(cfg.TokenEndpoint)

	form := url.Values{
		"client_id": {cfg.ClientID},
	}
	if cfg.Scope != "" {
		form.Set("scope", cfg.Scope)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create device auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("device auth request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read device auth response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device auth endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var dar DeviceAuthResponse
	if err := json.Unmarshal(body, &dar); err != nil {
		return nil, fmt.Errorf("failed to parse device auth response: %w", err)
	}

	if dar.Interval == 0 {
		dar.Interval = 5
	}
	if dar.ExpiresIn == 0 {
		dar.ExpiresIn = 300
	}

	return &dar, nil
}

// isRunningInContainer checks whether the process is running inside a container.
func isRunningInContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return true
	}
	for _, env := range []string{"container", "REMOTE_CONTAINERS", "CODESPACES"} {
		if os.Getenv(env) != "" {
			return true
		}
	}
	return false
}

// openBrowser attempts to open a URL in the default browser.
func openBrowser(url string) error {
	switch runtime.GOOS {
	case "linux":
		return exec.Command("xdg-open", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("cmd", "/c", "start", url).Start()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// PrintUserInstructions outputs the verification URI and user code.
// When not running inside a container, it also opens the URL in the default browser.
func PrintUserInstructions(dar *DeviceAuthResponse) {
	fmt.Println()
	fmt.Println("DEVICE AUTHORIZATION REQUIRED")
	fmt.Println()
	if dar.VerificationURIComplete != "" {
		fmt.Printf("Open the following URL in your browser:\n\n  %s\n\n", dar.VerificationURIComplete)
	} else {
		fmt.Printf("Open:  %s\n", dar.VerificationURI)
		fmt.Printf("Enter: %s\n\n", dar.UserCode)
	}

	if !isRunningInContainer() {
		browseURL := dar.VerificationURIComplete
		if browseURL == "" {
			browseURL = dar.VerificationURI
		}
		if err := openBrowser(browseURL); err == nil {
			fmt.Println("(Browser opened automatically)")
		}
	}

	fmt.Print("Waiting for authorization")
}

// PollForToken polls the token endpoint until the user authorizes, the code
// expires, or the context is cancelled.
func PollForToken(ctx context.Context, cfg *Config, deviceCode string, expiresIn, interval int) (*TokenResponse, error) {
	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	timeout := time.Duration(expiresIn) * time.Second
	if cfg.Timeout > 0 {
		timeout = time.Duration(cfg.Timeout) * time.Second
	}
	deadline := time.Now().Add(timeout)

	for {
		if time.Now().After(deadline) {
			fmt.Println()
			return nil, ErrTimeout
		}

		select {
		case <-ctx.Done():
			fmt.Println()
			return nil, ctx.Err()
		case <-time.After(time.Duration(interval) * time.Second):
		}

		form := url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {deviceCode},
			"client_id":   {cfg.ClientID},
		}
		if cfg.ClientSecret != "" {
			form.Set("client_secret", cfg.ClientSecret)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			fmt.Print("!")
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := client.Do(req)
		if err != nil {
			fmt.Print("!")
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			fmt.Print("!")
			continue
		}

		if resp.StatusCode == http.StatusOK {
			var tr TokenResponse
			if err := json.Unmarshal(body, &tr); err != nil {
				fmt.Println()
				return nil, fmt.Errorf("failed to parse token response: %w", err)
			}
			fmt.Println()
			return &tr, nil
		}

		var errResp tokenErrorResponse
		if err := json.Unmarshal(body, &errResp); err != nil {
			fmt.Print("!")
			continue
		}

		switch errResp.Error {
		case "authorization_pending":
			fmt.Print(".")
		case "slow_down":
			interval += 5
			fmt.Print(".")
		case "access_denied":
			fmt.Println()
			return nil, ErrDenied
		case "expired_token":
			fmt.Println()
			return nil, ErrTimeout
		default:
			fmt.Println()
			return nil, &ErrDeviceFlow{Code: errResp.Error, Message: errResp.ErrorDescription}
		}
	}
}
