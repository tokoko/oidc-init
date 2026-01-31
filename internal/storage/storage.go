package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	tokenDir    = ".oidc/cache/tokens"
	dirPerms    = 0700
	filePerms   = 0600
	expiryBuffer = 300 // seconds
)

// TokenData represents stored token metadata, compatible with the Python oidc-init format.
type TokenData struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresAt    string `json:"expires_at"`
	IssuedAt     string `json:"issued_at"`
	Scope        string `json:"scope,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// TokenResponse is the raw response from the token endpoint.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

func tokenDirPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, tokenDir), nil
}

func ensureTokenDir() (string, error) {
	dir, err := tokenDirPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, dirPerms); err != nil {
		return "", fmt.Errorf("cannot create token directory: %w", err)
	}
	return dir, nil
}

func jsonPath(dir, key string) string {
	return filepath.Join(dir, sanitizeKey(key)+".json")
}

func rawTokenPath(dir, key string) string {
	return filepath.Join(dir, sanitizeKey(key)+".token")
}

var nonSafeChars = regexp.MustCompile(`[^\w\-.]`)

func sanitizeKey(key string) string {
	return nonSafeChars.ReplaceAllString(key, "_")
}

// GenerateStorageKey returns the storage key for the given parameters.
// If profileName is non-empty, it is used directly. Otherwise a key is
// generated from the endpoint, realm, and clientID.
func GenerateStorageKey(endpoint, realm, clientID, profileName string) string {
	if profileName != "" {
		return profileName
	}
	ep := strings.TrimPrefix(endpoint, "https://")
	ep = strings.TrimPrefix(ep, "http://")
	ep = strings.ReplaceAll(ep, ":", "-")
	ep = strings.ReplaceAll(ep, "/", "-")
	return fmt.Sprintf("%s_%s_%s", ep, realm, clientID)
}

// SaveTokens persists the token response to disk as both a JSON metadata file
// and a raw access-token file.
func SaveTokens(key string, resp *TokenResponse) error {
	dir, err := ensureTokenDir()
	if err != nil {
		return err
	}

	now := time.Now().UTC()

	bufferSecs := expiryBuffer
	if resp.ExpiresIn > 0 {
		maxBuf := int(float64(resp.ExpiresIn) * 0.8)
		if maxBuf < bufferSecs {
			bufferSecs = maxBuf
		}
	}

	expiresAt := now.Add(time.Duration(resp.ExpiresIn-bufferSecs) * time.Second)

	data := TokenData{
		AccessToken:  resp.AccessToken,
		TokenType:    resp.TokenType,
		ExpiresAt:    expiresAt.Format(time.RFC3339),
		IssuedAt:     now.Format(time.RFC3339),
		Scope:        resp.Scope,
		RefreshToken: resp.RefreshToken,
		IDToken:      resp.IDToken,
	}

	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal token data: %w", err)
	}

	jp := jsonPath(dir, key)
	if err := os.WriteFile(jp, jsonBytes, filePerms); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}

	rp := rawTokenPath(dir, key)
	if err := os.WriteFile(rp, []byte(resp.AccessToken), filePerms); err != nil {
		return fmt.Errorf("failed to write raw token file: %w", err)
	}

	return nil
}

// GetTokens reads the stored token data for the given key.
func GetTokens(key string) (*TokenData, error) {
	dir, err := tokenDirPath()
	if err != nil {
		return nil, err
	}
	jp := jsonPath(dir, key)
	raw, err := os.ReadFile(jp)
	if err != nil {
		return nil, fmt.Errorf("token not found for key %q: %w", key, err)
	}
	var data TokenData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("failed to parse token file: %w", err)
	}
	return &data, nil
}

// GetMetadata is an alias for GetTokens (the JSON file contains all metadata).
func GetMetadata(key string) (*TokenData, error) {
	return GetTokens(key)
}

// IsExpired checks whether the token for the given key has expired.
func IsExpired(key string) (bool, error) {
	data, err := GetTokens(key)
	if err != nil {
		return true, err
	}
	expiresAt, err := time.Parse(time.RFC3339, data.ExpiresAt)
	if err != nil {
		return true, fmt.Errorf("failed to parse expires_at: %w", err)
	}
	return time.Now().UTC().After(expiresAt), nil
}

// TokenExists returns true if a token file exists for the given key.
func TokenExists(key string) bool {
	dir, err := tokenDirPath()
	if err != nil {
		return false
	}
	_, err = os.Stat(jsonPath(dir, key))
	return err == nil
}

// GetTokenFilePath returns the path to the raw .token file for the given key.
func GetTokenFilePath(key string) (string, error) {
	dir, err := tokenDirPath()
	if err != nil {
		return "", err
	}
	p := rawTokenPath(dir, key)
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("token file not found for key %q: %w", key, err)
	}
	return p, nil
}

// DeleteTokens removes both the JSON and raw token files for the given key.
func DeleteTokens(key string) error {
	dir, err := tokenDirPath()
	if err != nil {
		return err
	}
	jp := jsonPath(dir, key)
	rp := rawTokenPath(dir, key)

	errJSON := os.Remove(jp)
	errRaw := os.Remove(rp)

	if errJSON != nil && !os.IsNotExist(errJSON) {
		return fmt.Errorf("failed to delete token json: %w", errJSON)
	}
	if errRaw != nil && !os.IsNotExist(errRaw) {
		return fmt.Errorf("failed to delete raw token: %w", errRaw)
	}
	if os.IsNotExist(errJSON) && os.IsNotExist(errRaw) {
		return fmt.Errorf("no tokens found for key %q", key)
	}
	return nil
}

// PurgeAll removes all token files from the token directory.
func PurgeAll() error {
	dir, err := tokenDirPath()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read token directory: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			return fmt.Errorf("failed to remove %s: %w", e.Name(), err)
		}
	}
	return nil
}

// ListKeys returns the storage keys of all stored tokens.
func ListKeys() ([]string, error) {
	dir, err := tokenDirPath()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read token directory: %w", err)
	}
	seen := make(map[string]bool)
	var keys []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		ext := filepath.Ext(name)
		if ext != ".json" && ext != ".token" {
			continue
		}
		key := strings.TrimSuffix(name, ext)
		if !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}
	return keys, nil
}
