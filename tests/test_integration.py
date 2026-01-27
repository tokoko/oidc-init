"""Integration tests using Keycloak with ROPC grant.

These tests require a running Keycloak instance. They will be skipped
if Keycloak is not available.

To run these tests in the devcontainer:
    1. Ensure Keycloak is running (check docker compose)
    2. Run setup_keycloak.py to create realm/client/user:
       python scripts/setup_keycloak.py --create-test-user
    3. Run tests: uv run pytest tests/test_integration.py -v
"""

import os
import pytest
import requests
from typing import Dict, Any

from oidc_init.storage import TokenStorage


# Keycloak configuration - matches setup_keycloak.py defaults
KEYCLOAK_BASE_URL = os.environ.get("KEYCLOAK_URL", "http://keycloak:8080")
TEST_REALM = os.environ.get("TEST_REALM", "test-realm")
TEST_CLIENT_ID = os.environ.get("TEST_CLIENT_ID", "test-client")
TEST_USERNAME = os.environ.get("TEST_USERNAME", "testuser")
TEST_PASSWORD = os.environ.get("TEST_PASSWORD", "testpass")


def is_keycloak_available() -> bool:
    """Check if Keycloak is running and accessible."""
    try:
        response = requests.get(f"{KEYCLOAK_BASE_URL}/health/ready", timeout=2)
        return response.status_code == 200
    except requests.RequestException:
        return False


def get_tokens_via_ropc(
    scope: str = "openid profile email",
) -> Dict[str, Any]:
    """Get tokens using Resource Owner Password Credentials (ROPC) grant."""
    token_url = f"{KEYCLOAK_BASE_URL}/realms/{TEST_REALM}/protocol/openid-connect/token"
    response = requests.post(
        token_url,
        data={
            "grant_type": "password",
            "client_id": TEST_CLIENT_ID,
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD,
            "scope": scope,
        },
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


requires_keycloak = pytest.mark.skipif(
    not is_keycloak_available(),
    reason="Keycloak not available (set KEYCLOAK_URL or run in devcontainer)",
)


@requires_keycloak
class TestKeycloakIntegration:
    """Integration tests with real Keycloak instance."""

    def test_ropc_token_retrieval(self) -> None:
        """Test that we can get tokens from Keycloak via ROPC."""
        tokens = get_tokens_via_ropc()

        assert "access_token" in tokens
        assert "token_type" in tokens
        assert tokens["token_type"].lower() == "bearer"
        assert "expires_in" in tokens

    def test_store_keycloak_tokens(self, temp_token_storage: TokenStorage) -> None:
        """Test storing real Keycloak tokens."""
        tokens = get_tokens_via_ropc()
        storage_key = "keycloak-integration-test"

        temp_token_storage.save_tokens(storage_key, tokens, scope="openid profile email")

        # Verify tokens can be retrieved
        retrieved = temp_token_storage.get_tokens(storage_key)
        assert retrieved["access_token"] == tokens["access_token"]

        # Verify metadata
        metadata = temp_token_storage.get_metadata(storage_key)
        assert metadata["token_type"] == "Bearer"
        assert not temp_token_storage.is_expired(storage_key)

    def test_full_storage_workflow(self, temp_token_storage: TokenStorage) -> None:
        """Test complete workflow: get tokens, store, retrieve, verify not expired."""
        # Get tokens
        tokens = get_tokens_via_ropc()
        storage_key = "workflow-test"

        # Store
        temp_token_storage.save_tokens(storage_key, tokens)

        # List
        keys = temp_token_storage.list_storage_keys()
        assert storage_key in keys

        # Retrieve
        retrieved = temp_token_storage.get_tokens(storage_key)
        assert retrieved["access_token"] == tokens["access_token"]

        # Check not expired
        assert not temp_token_storage.is_expired(storage_key)

        # Get raw token file path
        token_path = temp_token_storage.get_token_file_path(storage_key)
        assert token_path.read_text() == tokens["access_token"]

        # Delete
        temp_token_storage.delete_tokens(storage_key)
        assert not temp_token_storage.token_exists(storage_key)

    def test_token_refresh_flow(self, temp_token_storage: TokenStorage) -> None:
        """Test that refresh tokens can be used to get new access tokens."""
        # Get initial tokens with offline_access for refresh token
        tokens = get_tokens_via_ropc(scope="openid profile email offline_access")

        if "refresh_token" not in tokens:
            pytest.skip("Refresh token not returned (offline_access scope may not be enabled)")

        # Use refresh token to get new access token
        token_url = f"{KEYCLOAK_BASE_URL}/realms/{TEST_REALM}/protocol/openid-connect/token"
        refresh_response = requests.post(
            token_url,
            data={
                "grant_type": "refresh_token",
                "client_id": TEST_CLIENT_ID,
                "refresh_token": tokens["refresh_token"],
            },
            timeout=10,
        )
        refresh_response.raise_for_status()
        new_tokens = refresh_response.json()

        assert "access_token" in new_tokens
        # Access token should be different after refresh
        assert new_tokens["access_token"] != tokens["access_token"]

    def test_token_introspection(self) -> None:
        """Test that tokens are valid via introspection endpoint."""
        tokens = get_tokens_via_ropc()

        # Introspect the token
        introspect_url = (
            f"{KEYCLOAK_BASE_URL}/realms/{TEST_REALM}/protocol/openid-connect/token/introspect"
        )
        response = requests.post(
            introspect_url,
            data={
                "token": tokens["access_token"],
                "client_id": TEST_CLIENT_ID,
            },
            timeout=10,
        )
        response.raise_for_status()
        introspection = response.json()

        assert introspection["active"] is True
        assert introspection["username"] == TEST_USERNAME
