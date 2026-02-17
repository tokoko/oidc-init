package profiles

import (
	"os"
	"path/filepath"
	"testing"
)

func setupTestHome(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	return tmp
}

func sampleProfile() *Profile {
	return &Profile{
		Endpoint: "keycloak.example.com",
		Realm:    "test-realm",
		ClientID: "test-client",
		Scope:    "openid profile email",
		Protocol: "https",
		Flow:     "device",
		Verify:   true,
	}
}

func TestAddAndGet(t *testing.T) {
	setupTestHome(t)
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	p := sampleProfile()
	if err := mgr.Add("test", p, false); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, err := mgr.Get("test")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if got.Endpoint != p.Endpoint {
		t.Errorf("Endpoint = %q, want %q", got.Endpoint, p.Endpoint)
	}
	if got.Realm != p.Realm {
		t.Errorf("Realm = %q, want %q", got.Realm, p.Realm)
	}
	if got.ClientID != p.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, p.ClientID)
	}
	if got.Scope != p.Scope {
		t.Errorf("Scope = %q, want %q", got.Scope, p.Scope)
	}
	if got.Protocol != p.Protocol {
		t.Errorf("Protocol = %q, want %q", got.Protocol, p.Protocol)
	}
	if got.Flow != p.Flow {
		t.Errorf("Flow = %q, want %q", got.Flow, p.Flow)
	}
	if got.Verify != p.Verify {
		t.Errorf("Verify = %v, want %v", got.Verify, p.Verify)
	}
}

func TestAdd_Duplicate_NoOverwrite(t *testing.T) {
	setupTestHome(t)
	mgr, _ := NewManager()
	_ = mgr.Add("test", sampleProfile(), false)

	err := mgr.Add("test", sampleProfile(), false)
	if err == nil {
		t.Error("expected error for duplicate add without overwrite")
	}
}

func TestAdd_Duplicate_WithOverwrite(t *testing.T) {
	setupTestHome(t)
	mgr, _ := NewManager()
	_ = mgr.Add("test", sampleProfile(), false)

	updated := &Profile{
		Endpoint: "new-endpoint.com",
		Realm:    "new-realm",
		ClientID: "new-client",
		Scope:    "openid",
		Protocol: "http",
		Flow:     "device",
		Verify:   false,
	}
	if err := mgr.Add("test", updated, true); err != nil {
		t.Fatalf("Add with overwrite: %v", err)
	}

	got, _ := mgr.Get("test")
	if got.Endpoint != "new-endpoint.com" {
		t.Errorf("Endpoint should be updated, got %q", got.Endpoint)
	}
}

func TestAdd_ReservedName(t *testing.T) {
	setupTestHome(t)
	mgr, _ := NewManager()

	err := mgr.Add("_reserved", sampleProfile(), false)
	if err == nil {
		t.Error("expected error for reserved name prefix")
	}
}

func TestGet_NotFound(t *testing.T) {
	setupTestHome(t)
	mgr, _ := NewManager()

	_, err := mgr.Get("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent profile")
	}
}

func TestList_Empty(t *testing.T) {
	setupTestHome(t)
	mgr, _ := NewManager()

	names, err := mgr.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("expected empty list, got %v", names)
	}
}

func TestList_Sorted(t *testing.T) {
	setupTestHome(t)
	mgr, _ := NewManager()
	for _, name := range []string{"charlie", "alice", "bob"} {
		_ = mgr.Add(name, sampleProfile(), false)
	}

	names, err := mgr.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	expected := []string{"alice", "bob", "charlie"}
	if len(names) != len(expected) {
		t.Fatalf("expected %d names, got %d", len(expected), len(names))
	}
	for i, name := range names {
		if name != expected[i] {
			t.Errorf("names[%d] = %q, want %q", i, name, expected[i])
		}
	}
}

func TestList_ExcludesReserved(t *testing.T) {
	setupTestHome(t)
	mgr, _ := NewManager()
	_ = mgr.Add("test", sampleProfile(), false)
	_ = mgr.SetDefault("test")

	names, _ := mgr.List()
	for _, name := range names {
		if name == defaultKey {
			t.Error("_default should not appear in List")
		}
	}
}

func TestDelete(t *testing.T) {
	setupTestHome(t)
	mgr, _ := NewManager()
	_ = mgr.Add("test", sampleProfile(), false)

	if err := mgr.Delete("test"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if mgr.Exists("test") {
		t.Error("profile should not exist after delete")
	}
}

func TestDelete_NotFound(t *testing.T) {
	setupTestHome(t)
	mgr, _ := NewManager()

	err := mgr.Delete("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent profile")
	}
}

func TestDelete_ClearsDefault(t *testing.T) {
	setupTestHome(t)
	mgr, _ := NewManager()
	_ = mgr.Add("first", sampleProfile(), false)
	_ = mgr.Add("second", sampleProfile(), false)
	_ = mgr.SetDefault("first")

	_ = mgr.Delete("first")

	def, _ := mgr.GetDefault()
	if def != "" {
		t.Errorf("default should be cleared after deleting default profile, got %q", def)
	}
}

func TestDelete_PreservesOtherDefault(t *testing.T) {
	setupTestHome(t)
	mgr, _ := NewManager()
	_ = mgr.Add("first", sampleProfile(), false)
	_ = mgr.Add("second", sampleProfile(), false)
	_ = mgr.SetDefault("first")

	_ = mgr.Delete("second")

	def, _ := mgr.GetDefault()
	if def != "first" {
		t.Errorf("default should still be 'first', got %q", def)
	}
}

func TestSetDefault(t *testing.T) {
	setupTestHome(t)
	mgr, _ := NewManager()
	_ = mgr.Add("test", sampleProfile(), false)

	if err := mgr.SetDefault("test"); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}

	def, _ := mgr.GetDefault()
	if def != "test" {
		t.Errorf("GetDefault = %q, want 'test'", def)
	}
}

func TestSetDefault_NotFound(t *testing.T) {
	setupTestHome(t)
	mgr, _ := NewManager()

	err := mgr.SetDefault("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent profile")
	}
}

func TestUnsetDefault(t *testing.T) {
	setupTestHome(t)
	mgr, _ := NewManager()
	_ = mgr.Add("test", sampleProfile(), false)
	_ = mgr.SetDefault("test")

	if err := mgr.UnsetDefault(); err != nil {
		t.Fatalf("UnsetDefault: %v", err)
	}

	def, _ := mgr.GetDefault()
	if def != "" {
		t.Errorf("default should be empty after unset, got %q", def)
	}
}

func TestUnsetDefault_NoneSet(t *testing.T) {
	setupTestHome(t)
	mgr, _ := NewManager()

	err := mgr.UnsetDefault()
	if err == nil {
		t.Error("expected error when no default is set")
	}
}

func TestGetDefault_NoneSet(t *testing.T) {
	setupTestHome(t)
	mgr, _ := NewManager()

	def, err := mgr.GetDefault()
	if err != nil {
		t.Fatalf("GetDefault: %v", err)
	}
	if def != "" {
		t.Errorf("expected empty string, got %q", def)
	}
}

func TestFilePermissions(t *testing.T) {
	home := setupTestHome(t)
	mgr, _ := NewManager()
	_ = mgr.Add("test", sampleProfile(), false)

	info, err := os.Stat(filepath.Join(home, profileDir, profileFile))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("profiles.json permissions = %o, want 0600", perm)
	}
}
