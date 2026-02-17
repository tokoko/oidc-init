package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setupTestHome(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	return tmp
}

func sampleTokenResponse() *TokenResponse {
	return &TokenResponse{
		AccessToken:  "eyJhbGciOiJSUzI1NiJ9.access",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "eyJhbGciOiJSUzI1NiJ9.refresh",
		Scope:        "openid profile email",
		IDToken:      "eyJhbGciOiJSUzI1NiJ9.id",
	}
}

func TestGenerateStorageKey_WithProfile(t *testing.T) {
	key := GenerateStorageKey("host:8080", "realm", "client", "myprofile")
	if key != "myprofile" {
		t.Errorf("expected 'myprofile', got %q", key)
	}
}

func TestGenerateStorageKey_WithoutProfile(t *testing.T) {
	key := GenerateStorageKey("host:8080", "realm", "client", "")
	if key != "host-8080_realm_client" {
		t.Errorf("expected 'host-8080_realm_client', got %q", key)
	}
}

func TestGenerateStorageKey_StripsProtocol(t *testing.T) {
	for _, prefix := range []string{"https://", "http://"} {
		key := GenerateStorageKey(prefix+"host:8080", "realm", "client", "")
		if strings.Contains(key, "http") {
			t.Errorf("key should not contain protocol prefix, got %q", key)
		}
	}
}

func TestSaveAndGetTokens(t *testing.T) {
	setupTestHome(t)
	resp := sampleTokenResponse()

	if err := SaveTokens("testkey", resp); err != nil {
		t.Fatalf("SaveTokens: %v", err)
	}

	data, err := GetTokens("testkey")
	if err != nil {
		t.Fatalf("GetTokens: %v", err)
	}

	if data.AccessToken != resp.AccessToken {
		t.Errorf("AccessToken mismatch: got %q", data.AccessToken)
	}
	if data.TokenType != resp.TokenType {
		t.Errorf("TokenType mismatch: got %q", data.TokenType)
	}
	if data.RefreshToken != resp.RefreshToken {
		t.Errorf("RefreshToken mismatch: got %q", data.RefreshToken)
	}
	if data.IDToken != resp.IDToken {
		t.Errorf("IDToken mismatch: got %q", data.IDToken)
	}
	if data.Scope != resp.Scope {
		t.Errorf("Scope mismatch: got %q", data.Scope)
	}
	if data.ExpiresAt == "" {
		t.Error("ExpiresAt should not be empty")
	}
	if data.IssuedAt == "" {
		t.Error("IssuedAt should not be empty")
	}
}

func TestSaveTokens_CreatesFiles(t *testing.T) {
	home := setupTestHome(t)
	if err := SaveTokens("testkey", sampleTokenResponse()); err != nil {
		t.Fatalf("SaveTokens: %v", err)
	}

	dir := filepath.Join(home, tokenDir)
	jsonFile := filepath.Join(dir, "testkey.json")
	tokenFile := filepath.Join(dir, "testkey.token")

	if _, err := os.Stat(jsonFile); err != nil {
		t.Errorf("json file not found: %v", err)
	}
	if _, err := os.Stat(tokenFile); err != nil {
		t.Errorf("token file not found: %v", err)
	}
}

func TestSaveTokens_RawTokenContent(t *testing.T) {
	home := setupTestHome(t)
	resp := sampleTokenResponse()
	if err := SaveTokens("testkey", resp); err != nil {
		t.Fatalf("SaveTokens: %v", err)
	}

	tokenFile := filepath.Join(home, tokenDir, "testkey.token")
	content, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(content) != resp.AccessToken {
		t.Errorf("raw token file content = %q, want %q", string(content), resp.AccessToken)
	}
}

func TestSaveTokens_FilePermissions(t *testing.T) {
	home := setupTestHome(t)
	if err := SaveTokens("testkey", sampleTokenResponse()); err != nil {
		t.Fatalf("SaveTokens: %v", err)
	}

	dir := filepath.Join(home, tokenDir)
	for _, name := range []string{"testkey.json", "testkey.token"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("Stat %s: %v", name, err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Errorf("%s permissions = %o, want 0600", name, perm)
		}
	}
}

func TestSaveTokens_DirectoryPermissions(t *testing.T) {
	home := setupTestHome(t)
	if err := SaveTokens("testkey", sampleTokenResponse()); err != nil {
		t.Fatalf("SaveTokens: %v", err)
	}

	dir := filepath.Join(home, tokenDir)
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0700 {
		t.Errorf("directory permissions = %o, want 0700", perm)
	}
}

func TestSaveTokens_ExpiryBuffer(t *testing.T) {
	setupTestHome(t)
	now := time.Now().UTC()
	resp := &TokenResponse{
		AccessToken: "tok",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}
	if err := SaveTokens("testkey", resp); err != nil {
		t.Fatalf("SaveTokens: %v", err)
	}

	data, _ := GetTokens("testkey")
	expiresAt, _ := time.Parse(time.RFC3339, data.ExpiresAt)
	expected := now.Add(time.Duration(3600-300) * time.Second)
	diff := expiresAt.Sub(expected)
	if diff < -2*time.Second || diff > 2*time.Second {
		t.Errorf("ExpiresAt = %v, expected ~%v (diff: %v)", expiresAt, expected, diff)
	}
}

func TestSaveTokens_ExpiryBuffer_ShortLived(t *testing.T) {
	setupTestHome(t)
	now := time.Now().UTC()
	resp := &TokenResponse{
		AccessToken: "tok",
		TokenType:   "Bearer",
		ExpiresIn:   10,
	}
	if err := SaveTokens("testkey", resp); err != nil {
		t.Fatalf("SaveTokens: %v", err)
	}

	data, _ := GetTokens("testkey")
	expiresAt, _ := time.Parse(time.RFC3339, data.ExpiresAt)
	// buffer = min(300, int(10*0.8)) = min(300, 8) = 8, effective = 10-8 = 2s
	expected := now.Add(2 * time.Second)
	diff := expiresAt.Sub(expected)
	if diff < -2*time.Second || diff > 2*time.Second {
		t.Errorf("ExpiresAt = %v, expected ~%v (diff: %v)", expiresAt, expected, diff)
	}
}

func TestGetTokens_NotFound(t *testing.T) {
	setupTestHome(t)
	_, err := GetTokens("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent key")
	}
}

func TestIsExpired_Fresh(t *testing.T) {
	setupTestHome(t)
	resp := sampleTokenResponse() // ExpiresIn: 3600
	if err := SaveTokens("testkey", resp); err != nil {
		t.Fatalf("SaveTokens: %v", err)
	}

	expired, err := IsExpired("testkey")
	if err != nil {
		t.Fatalf("IsExpired: %v", err)
	}
	if expired {
		t.Error("token should not be expired")
	}
}

func TestIsExpired_Expired(t *testing.T) {
	setupTestHome(t)
	resp := &TokenResponse{
		AccessToken: "tok",
		TokenType:   "Bearer",
		ExpiresIn:   1, // buffer = min(300, 0) = 0, effective = 1s
	}
	if err := SaveTokens("testkey", resp); err != nil {
		t.Fatalf("SaveTokens: %v", err)
	}

	time.Sleep(1200 * time.Millisecond)

	expired, err := IsExpired("testkey")
	if err != nil {
		t.Fatalf("IsExpired: %v", err)
	}
	if !expired {
		t.Error("token should be expired")
	}
}

func TestTokenExists(t *testing.T) {
	setupTestHome(t)

	if TokenExists("testkey") {
		t.Error("should not exist before save")
	}

	if err := SaveTokens("testkey", sampleTokenResponse()); err != nil {
		t.Fatalf("SaveTokens: %v", err)
	}

	if !TokenExists("testkey") {
		t.Error("should exist after save")
	}
}

func TestGetTokenFilePath(t *testing.T) {
	setupTestHome(t)
	if err := SaveTokens("testkey", sampleTokenResponse()); err != nil {
		t.Fatalf("SaveTokens: %v", err)
	}

	p, err := GetTokenFilePath("testkey")
	if err != nil {
		t.Fatalf("GetTokenFilePath: %v", err)
	}
	if !strings.HasSuffix(p, ".token") {
		t.Errorf("path should end in .token, got %q", p)
	}
}

func TestGetTokenFilePath_NotFound(t *testing.T) {
	setupTestHome(t)
	_, err := GetTokenFilePath("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent key")
	}
}

func TestDeleteTokens(t *testing.T) {
	setupTestHome(t)
	if err := SaveTokens("testkey", sampleTokenResponse()); err != nil {
		t.Fatalf("SaveTokens: %v", err)
	}

	if err := DeleteTokens("testkey"); err != nil {
		t.Fatalf("DeleteTokens: %v", err)
	}

	if TokenExists("testkey") {
		t.Error("token should not exist after delete")
	}
}

func TestDeleteTokens_NotFound(t *testing.T) {
	setupTestHome(t)
	err := DeleteTokens("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent key")
	}
}

func TestPurgeAll(t *testing.T) {
	setupTestHome(t)
	for _, key := range []string{"key1", "key2", "key3"} {
		if err := SaveTokens(key, sampleTokenResponse()); err != nil {
			t.Fatalf("SaveTokens(%s): %v", key, err)
		}
	}

	if err := PurgeAll(); err != nil {
		t.Fatalf("PurgeAll: %v", err)
	}

	keys, _ := ListKeys()
	if len(keys) != 0 {
		t.Errorf("expected 0 keys after purge, got %d", len(keys))
	}
}

func TestPurgeAll_Empty(t *testing.T) {
	setupTestHome(t)
	// Ensure token dir exists but is empty.
	if err := SaveTokens("tmp", sampleTokenResponse()); err != nil {
		t.Fatalf("SaveTokens: %v", err)
	}
	_ = PurgeAll()

	if err := PurgeAll(); err != nil {
		t.Errorf("PurgeAll on empty dir should not error: %v", err)
	}
}

func TestPurgeAll_NoDirYet(t *testing.T) {
	setupTestHome(t)
	if err := PurgeAll(); err != nil {
		t.Errorf("PurgeAll with no dir should not error: %v", err)
	}
}

func TestListKeys(t *testing.T) {
	setupTestHome(t)
	want := []string{"alpha", "beta", "gamma"}
	for _, key := range want {
		if err := SaveTokens(key, sampleTokenResponse()); err != nil {
			t.Fatalf("SaveTokens(%s): %v", key, err)
		}
	}

	keys, err := ListKeys()
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != len(want) {
		t.Fatalf("expected %d keys, got %d: %v", len(want), len(keys), keys)
	}

	// Check all expected keys present (order not guaranteed).
	keySet := make(map[string]bool)
	for _, k := range keys {
		keySet[k] = true
	}
	for _, w := range want {
		if !keySet[w] {
			t.Errorf("key %q not found in %v", w, keys)
		}
	}
}

func TestListKeys_Empty(t *testing.T) {
	setupTestHome(t)
	keys, err := ListKeys()
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if keys != nil && len(keys) != 0 {
		t.Errorf("expected nil or empty, got %v", keys)
	}
}
