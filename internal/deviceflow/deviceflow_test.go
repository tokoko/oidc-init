package deviceflow

import (
	"strings"
	"testing"
)

func TestDeviceAuthEndpoint(t *testing.T) {
	tests := []struct {
		tokenEndpoint string
		want          string
	}{
		{
			"https://keycloak:8080/realms/test-realm/protocol/openid-connect/token",
			"https://keycloak:8080/realms/test-realm/protocol/openid-connect/auth/device",
		},
		{
			"http://localhost:8080/realms/master/protocol/openid-connect/token",
			"http://localhost:8080/realms/master/protocol/openid-connect/auth/device",
		},
	}
	for _, tt := range tests {
		got := deviceAuthEndpoint(tt.tokenEndpoint)
		if got != tt.want {
			t.Errorf("deviceAuthEndpoint(%q) = %q, want %q", tt.tokenEndpoint, got, tt.want)
		}
	}
}

func TestErrDeviceFlow_WithMessage(t *testing.T) {
	e := &ErrDeviceFlow{Code: "invalid_grant", Message: "grant expired"}
	s := e.Error()
	if !strings.Contains(s, "invalid_grant") {
		t.Errorf("error should contain code, got %q", s)
	}
	if !strings.Contains(s, "grant expired") {
		t.Errorf("error should contain message, got %q", s)
	}
}

func TestErrDeviceFlow_WithoutMessage(t *testing.T) {
	e := &ErrDeviceFlow{Code: "invalid_grant", Message: ""}
	s := e.Error()
	if !strings.Contains(s, "invalid_grant") {
		t.Errorf("error should contain code, got %q", s)
	}
}
