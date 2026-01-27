"""Unit tests for token storage."""

import pytest
from typing import Dict, Any

from oidc_init.storage import TokenStorage, TokenNotFoundError, StorageError


class TestTokenStorage:
    """Tests for TokenStorage class."""

    def test_save_and_get_tokens(
        self, temp_token_storage: TokenStorage, sample_tokens: Dict[str, Any]
    ) -> None:
        """Test saving and retrieving tokens."""
        storage_key = "test-profile"

        temp_token_storage.save_tokens(storage_key, sample_tokens)
        retrieved = temp_token_storage.get_tokens(storage_key)

        assert retrieved["access_token"] == sample_tokens["access_token"]
        assert retrieved["token_type"] == "Bearer"
        assert "refresh_token" in retrieved
        assert "id_token" in retrieved

    def test_get_tokens_not_found(self, temp_token_storage: TokenStorage) -> None:
        """Test that TokenNotFoundError is raised for missing tokens."""
        with pytest.raises(TokenNotFoundError):
            temp_token_storage.get_tokens("nonexistent")

    def test_token_expiry(
        self, temp_token_storage: TokenStorage, sample_tokens: Dict[str, Any]
    ) -> None:
        """Test token expiry detection."""
        import time

        storage_key = "expiry-test"

        # Save tokens with 1 hour expiry
        temp_token_storage.save_tokens(storage_key, sample_tokens)
        assert not temp_token_storage.is_expired(storage_key)

        # Save tokens with very short expiry and minimal buffer
        # Buffer is min(300, int(2 * 0.8)) = 1, so effective expiry = 2 - 1 = 1 second
        short_expiry_tokens = {**sample_tokens, "expires_in": 2}
        temp_token_storage.save_tokens(storage_key, short_expiry_tokens, expiry_buffer_seconds=1)
        # Wait for expiry
        time.sleep(1.1)
        assert temp_token_storage.is_expired(storage_key)

    def test_get_metadata(
        self, temp_token_storage: TokenStorage, sample_tokens: Dict[str, Any]
    ) -> None:
        """Test retrieving token metadata without sensitive data."""
        storage_key = "metadata-test"
        temp_token_storage.save_tokens(storage_key, sample_tokens, scope="openid profile")

        metadata = temp_token_storage.get_metadata(storage_key)

        assert metadata["token_type"] == "Bearer"
        assert metadata["has_refresh_token"] is True
        assert metadata["has_id_token"] is True
        assert metadata["scope"] == "openid profile"
        assert "access_token" not in metadata

    def test_delete_tokens(
        self, temp_token_storage: TokenStorage, sample_tokens: Dict[str, Any]
    ) -> None:
        """Test deleting tokens."""
        storage_key = "delete-test"
        temp_token_storage.save_tokens(storage_key, sample_tokens)

        assert temp_token_storage.token_exists(storage_key)
        temp_token_storage.delete_tokens(storage_key)
        assert not temp_token_storage.token_exists(storage_key)

    def test_delete_nonexistent_tokens(self, temp_token_storage: TokenStorage) -> None:
        """Test deleting nonexistent tokens raises error."""
        with pytest.raises(TokenNotFoundError):
            temp_token_storage.delete_tokens("nonexistent")

    def test_list_storage_keys(
        self, temp_token_storage: TokenStorage, sample_tokens: Dict[str, Any]
    ) -> None:
        """Test listing all storage keys."""
        temp_token_storage.save_tokens("profile-a", sample_tokens)
        temp_token_storage.save_tokens("profile-b", sample_tokens)
        temp_token_storage.save_tokens("profile-c", sample_tokens)

        keys = temp_token_storage.list_storage_keys()
        assert sorted(keys) == ["profile-a", "profile-b", "profile-c"]

    def test_purge_all_tokens(
        self, temp_token_storage: TokenStorage, sample_tokens: Dict[str, Any]
    ) -> None:
        """Test purging all tokens."""
        temp_token_storage.save_tokens("profile-1", sample_tokens)
        temp_token_storage.save_tokens("profile-2", sample_tokens)

        count = temp_token_storage.purge_all_tokens()
        assert count == 2
        assert temp_token_storage.list_storage_keys() == []

    def test_generate_storage_key_with_profile(self, temp_token_storage: TokenStorage) -> None:
        """Test storage key generation with profile name."""
        key = temp_token_storage.generate_storage_key(
            endpoint="keycloak:8080",
            realm="test-realm",
            client_id="test-client",
            profile_name="my-profile",
        )
        assert key == "my-profile"

    def test_generate_storage_key_without_profile(self, temp_token_storage: TokenStorage) -> None:
        """Test storage key generation without profile name."""
        key = temp_token_storage.generate_storage_key(
            endpoint="keycloak:8080",
            realm="test-realm",
            client_id="test-client",
        )
        assert "keycloak" in key
        assert "test-realm" in key
        assert "test-client" in key

    def test_raw_token_file_created(
        self, temp_token_storage: TokenStorage, sample_tokens: Dict[str, Any]
    ) -> None:
        """Test that raw .token file is created alongside JSON."""
        storage_key = "raw-token-test"
        temp_token_storage.save_tokens(storage_key, sample_tokens)

        token_path = temp_token_storage.get_token_file_path(storage_key)
        assert token_path.exists()
        assert token_path.suffix == ".token"

        # Check content is just the access token (no JSON, no newline)
        content = token_path.read_text()
        assert content == sample_tokens["access_token"]
        assert "\n" not in content

    def test_file_permissions(
        self, temp_token_storage: TokenStorage, sample_tokens: Dict[str, Any]
    ) -> None:
        """Test that token files have restrictive permissions."""
        import stat

        storage_key = "permissions-test"
        temp_token_storage.save_tokens(storage_key, sample_tokens)

        # Check directory permissions (0700)
        dir_mode = temp_token_storage.tokens_dir.stat().st_mode
        assert stat.S_IMODE(dir_mode) == 0o700

        # Check JSON file permissions (0600)
        json_path = temp_token_storage._get_token_file_path(storage_key)
        json_mode = json_path.stat().st_mode
        assert stat.S_IMODE(json_mode) == 0o600

    def test_save_tokens_without_access_token(self, temp_token_storage: TokenStorage) -> None:
        """Test that saving without access_token raises error."""
        with pytest.raises(StorageError, match="must contain 'access_token'"):
            temp_token_storage.save_tokens("test", {"token_type": "Bearer"})
