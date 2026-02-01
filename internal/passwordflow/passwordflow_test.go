package passwordflow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestToken_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if got := r.FormValue("grant_type"); got != "password" {
			t.Errorf("grant_type = %q, want %q", got, "password")
		}
		if got := r.FormValue("username"); got != "testuser" {
			t.Errorf("username = %q, want %q", got, "testuser")
		}
		if got := r.FormValue("password"); got != "testpass" {
			t.Errorf("password = %q, want %q", got, "testpass")
		}
		if got := r.FormValue("client_id"); got != "my-client" {
			t.Errorf("client_id = %q, want %q", got, "my-client")
		}
		if got := r.FormValue("client_secret"); got != "my-secret" {
			t.Errorf("client_secret = %q, want %q", got, "my-secret")
		}
		if got := r.FormValue("scope"); got != "openid" {
			t.Errorf("scope = %q, want %q", got, "openid")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  "access-tok",
			TokenType:    "Bearer",
			ExpiresIn:    300,
			RefreshToken: "refresh-tok",
			Scope:        "openid",
			IDToken:      "id-tok",
		})
	}))
	defer server.Close()

	cfg := &Config{
		TokenEndpoint: server.URL,
		ClientID:      "my-client",
		ClientSecret:  "my-secret",
		Username:      "testuser",
		Scope:         "openid",
		HTTPClient:    server.Client(),
	}

	resp, err := RequestToken(context.Background(), cfg, "testpass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AccessToken != "access-tok" {
		t.Errorf("AccessToken = %q, want %q", resp.AccessToken, "access-tok")
	}
	if resp.RefreshToken != "refresh-tok" {
		t.Errorf("RefreshToken = %q, want %q", resp.RefreshToken, "refresh-tok")
	}
	if resp.IDToken != "id-tok" {
		t.Errorf("IDToken = %q, want %q", resp.IDToken, "id-tok")
	}
}

func TestRequestToken_NoClientSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if got := r.FormValue("client_secret"); got != "" {
			t.Errorf("client_secret should be empty, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "tok",
			TokenType:   "Bearer",
			ExpiresIn:   300,
		})
	}))
	defer server.Close()

	cfg := &Config{
		TokenEndpoint: server.URL,
		ClientID:      "pub-client",
		Username:      "user",
		Scope:         "openid",
		HTTPClient:    server.Client(),
	}

	_, err := RequestToken(context.Background(), cfg, "pass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRequestToken_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "Invalid user credentials",
		})
	}))
	defer server.Close()

	cfg := &Config{
		TokenEndpoint: server.URL,
		ClientID:      "my-client",
		Username:      "baduser",
		HTTPClient:    server.Client(),
	}

	_, err := RequestToken(context.Background(), cfg, "badpass")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got != "authentication failed: Invalid user credentials (invalid_grant)" {
		t.Errorf("unexpected error message: %q", got)
	}
}

func TestRequestToken_ErrorResponseNoDescription(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenErrorResponse{
			Error: "unsupported_grant_type",
		})
	}))
	defer server.Close()

	cfg := &Config{
		TokenEndpoint: server.URL,
		ClientID:      "my-client",
		Username:      "user",
		HTTPClient:    server.Client(),
	}

	_, err := RequestToken(context.Background(), cfg, "pass")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := err.Error(); got != "authentication failed: unsupported_grant_type" {
		t.Errorf("unexpected error message: %q", got)
	}
}

func TestRequestToken_ContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{AccessToken: "tok", TokenType: "Bearer", ExpiresIn: 300})
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfg := &Config{
		TokenEndpoint: server.URL,
		ClientID:      "my-client",
		Username:      "user",
		HTTPClient:    server.Client(),
	}

	_, err := RequestToken(ctx, cfg, "pass")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}
