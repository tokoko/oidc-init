//go:build integration

package deviceflow

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

const (
	keycloakURL  = "http://localhost:8080"
	testRealm    = "test-realm"
	testClientID = "test-client"
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

func TestRequestDeviceCode(t *testing.T) {
	skipIfNoKeycloak(t)

	tokenEndpoint := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", keycloakURL, testRealm)
	cfg := &Config{
		TokenEndpoint: tokenEndpoint,
		ClientID:      testClientID,
		Scope:         "openid profile email",
		HTTPClient:    &http.Client{Timeout: 10 * time.Second},
	}

	dar, err := RequestDeviceCode(context.Background(), cfg)
	if err != nil {
		t.Fatalf("RequestDeviceCode: %v", err)
	}

	if dar.DeviceCode == "" {
		t.Error("DeviceCode should not be empty")
	}
	if dar.UserCode == "" {
		t.Error("UserCode should not be empty")
	}
	if dar.VerificationURI == "" {
		t.Error("VerificationURI should not be empty")
	}
	if dar.ExpiresIn <= 0 {
		t.Errorf("ExpiresIn should be positive, got %d", dar.ExpiresIn)
	}
	if dar.Interval <= 0 {
		t.Errorf("Interval should be positive, got %d", dar.Interval)
	}
}

func TestRequestDeviceCode_InvalidClient(t *testing.T) {
	skipIfNoKeycloak(t)

	tokenEndpoint := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", keycloakURL, testRealm)
	cfg := &Config{
		TokenEndpoint: tokenEndpoint,
		ClientID:      "bogus-nonexistent-client",
		HTTPClient:    &http.Client{Timeout: 10 * time.Second},
	}

	_, err := RequestDeviceCode(context.Background(), cfg)
	if err == nil {
		t.Error("expected error for invalid client ID")
	}
}
