//go:build integration

package storage

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	keycloakURL  = "http://localhost:8080"
	testRealm    = "test-realm"
	testClientID = "test-client"
	testUsername  = "testuser"
	testPassword = "testpass"
)

func skipIfNoKeycloak(t *testing.T) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(keycloakURL + "/realms/master")
	if err != nil {
		t.Skipf("Keycloak not reachable: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Skipf("Keycloak not ready: status %d", resp.StatusCode)
	}
}

func getTokensViaROPC(t *testing.T, scope string) map[string]any {
	t.Helper()

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", keycloakURL, testRealm)
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {testClientID},
		"username":   {testUsername},
		"password":   {testPassword},
	}
	if scope != "" {
		form.Set("scope", scope)
	}

	resp, err := http.PostForm(tokenURL, form)
	if err != nil {
		t.Fatalf("ROPC request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ROPC returned %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("failed to parse ROPC response: %v", err)
	}
	return result
}

func TestIntegration_ROPCTokenRetrieval(t *testing.T) {
	skipIfNoKeycloak(t)

	tokens := getTokensViaROPC(t, "openid profile email")

	if _, ok := tokens["access_token"]; !ok {
		t.Error("response missing access_token")
	}
	if tt, _ := tokens["token_type"].(string); !strings.EqualFold(tt, "Bearer") {
		t.Errorf("token_type = %q, want Bearer", tt)
	}
	if _, ok := tokens["expires_in"]; !ok {
		t.Error("response missing expires_in")
	}
}

func TestIntegration_StoreAndRetrieveTokens(t *testing.T) {
	skipIfNoKeycloak(t)
	setupTestHome(t)

	tokens := getTokensViaROPC(t, "openid profile email")

	expiresIn := int(tokens["expires_in"].(float64))
	resp := &TokenResponse{
		AccessToken: tokens["access_token"].(string),
		TokenType:   tokens["token_type"].(string),
		ExpiresIn:   expiresIn,
	}
	if rt, ok := tokens["refresh_token"].(string); ok {
		resp.RefreshToken = rt
	}
	if scope, ok := tokens["scope"].(string); ok {
		resp.Scope = scope
	}

	key := "integration-test"
	if err := SaveTokens(key, resp); err != nil {
		t.Fatalf("SaveTokens: %v", err)
	}

	data, err := GetTokens(key)
	if err != nil {
		t.Fatalf("GetTokens: %v", err)
	}
	if data.AccessToken != resp.AccessToken {
		t.Error("access token mismatch after round-trip")
	}
}

func TestIntegration_FullWorkflow(t *testing.T) {
	skipIfNoKeycloak(t)
	setupTestHome(t)

	tokens := getTokensViaROPC(t, "openid profile email")

	expiresIn := int(tokens["expires_in"].(float64))
	resp := &TokenResponse{
		AccessToken: tokens["access_token"].(string),
		TokenType:   tokens["token_type"].(string),
		ExpiresIn:   expiresIn,
	}
	if scope, ok := tokens["scope"].(string); ok {
		resp.Scope = scope
	}

	key := "workflow-test"

	// Save.
	if err := SaveTokens(key, resp); err != nil {
		t.Fatalf("SaveTokens: %v", err)
	}

	// List.
	keys, err := ListKeys()
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	found := false
	for _, k := range keys {
		if k == key {
			found = true
		}
	}
	if !found {
		t.Errorf("key %q not in ListKeys result: %v", key, keys)
	}

	// Get.
	data, err := GetTokens(key)
	if err != nil {
		t.Fatalf("GetTokens: %v", err)
	}
	if data.AccessToken != resp.AccessToken {
		t.Error("access token mismatch")
	}

	// Not expired.
	expired, err := IsExpired(key)
	if err != nil {
		t.Fatalf("IsExpired: %v", err)
	}
	if expired {
		t.Error("fresh token should not be expired")
	}

	// Raw token file.
	p, err := GetTokenFilePath(key)
	if err != nil {
		t.Fatalf("GetTokenFilePath: %v", err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(raw) != resp.AccessToken {
		t.Error("raw token file content mismatch")
	}

	// Delete.
	if err := DeleteTokens(key); err != nil {
		t.Fatalf("DeleteTokens: %v", err)
	}
	if TokenExists(key) {
		t.Error("token should not exist after delete")
	}
}
