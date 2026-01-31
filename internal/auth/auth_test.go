package auth

import "testing"

func TestBuildTokenEndpoint_BareHost(t *testing.T) {
	got := BuildTokenEndpoint("keycloak:8080", "test-realm", "https")
	want := "https://keycloak:8080/realms/test-realm/protocol/openid-connect/token"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildTokenEndpoint_HttpProtocol(t *testing.T) {
	got := BuildTokenEndpoint("keycloak:8080", "test-realm", "http")
	want := "http://keycloak:8080/realms/test-realm/protocol/openid-connect/token"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildTokenEndpoint_ExplicitScheme(t *testing.T) {
	got := BuildTokenEndpoint("https://keycloak.example.com", "myrealm", "http")
	want := "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token"
	if got != want {
		t.Errorf("explicit scheme should take precedence: got %q, want %q", got, want)
	}
}

func TestBuildTokenEndpoint_TrailingSlash(t *testing.T) {
	got := BuildTokenEndpoint("https://keycloak.example.com/", "realm", "https")
	want := "https://keycloak.example.com/realms/realm/protocol/openid-connect/token"
	if got != want {
		t.Errorf("trailing slash should be stripped: got %q, want %q", got, want)
	}
}
