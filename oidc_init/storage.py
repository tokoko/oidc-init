"""Token storage management using local file system."""

import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List


class StorageError(Exception):
    """Base exception for storage-related errors."""

    pass


class TokenNotFoundError(StorageError):
    """Raised when a token doesn't exist."""

    pass


# Default token storage directory
DEFAULT_TOKEN_DIR = Path.home() / ".oidc" / "cache"
DEFAULT_TOKENS_DIR = DEFAULT_TOKEN_DIR / "tokens"


class TokenStorage:
    """Manage OIDC token storage in local file system."""

    def __init__(self, tokens_dir: Optional[Path] = None):
        """Initialize the token storage.

        Args:
            tokens_dir: Path to the tokens directory (default: ~/.oidc/cache/tokens)
        """
        self.tokens_dir = tokens_dir or DEFAULT_TOKENS_DIR

    def _ensure_token_dir(self) -> None:
        """Ensure the tokens directory exists with proper permissions."""
        self.tokens_dir.mkdir(parents=True, exist_ok=True)
        # Set directory permissions to 700 (owner rwx only)
        os.chmod(self.tokens_dir, 0o700)

    def _sanitize_storage_key(self, storage_key: str) -> str:
        """Sanitize storage key for use in filename.

        Args:
            storage_key: Storage key

        Returns:
            Sanitized key safe for filesystem
        """
        return re.sub(r'[^\w\-.]', '_', storage_key)

    def _get_token_file_path(self, storage_key: str) -> Path:
        """Get the JSON file path for a storage key.

        Args:
            storage_key: Storage key

        Returns:
            Path to the token JSON file
        """
        safe_key = self._sanitize_storage_key(storage_key)
        return self.tokens_dir / f"{safe_key}.json"

    def _get_raw_token_file_path(self, storage_key: str) -> Path:
        """Get the raw token file path for a storage key.

        This file contains only the access token string (no JSON, no newline).

        Args:
            storage_key: Storage key

        Returns:
            Path to the raw token file
        """
        safe_key = self._sanitize_storage_key(storage_key)
        return self.tokens_dir / f"{safe_key}.token"

    def _load_token_data(self, storage_key: str) -> Dict[str, Any]:
        """Load token data from file.

        Args:
            storage_key: Key to load tokens for

        Returns:
            Dictionary containing token data

        Raises:
            TokenNotFoundError: If token file doesn't exist
            StorageError: If file read fails
        """
        token_file = self._get_token_file_path(storage_key)

        if not token_file.exists():
            raise TokenNotFoundError(
                f"No tokens found for '{storage_key}'. Run 'oidc init' to authenticate."
            )

        try:
            with open(token_file, "r") as f:
                data = json.load(f)
                if not isinstance(data, dict):
                    raise StorageError(
                        f"Invalid token file format for '{storage_key}': expected dict, got {type(data)}"
                    )
                return data
        except json.JSONDecodeError as e:
            raise StorageError(f"Failed to parse token file for '{storage_key}': {e}") from e
        except IOError as e:
            raise StorageError(f"Failed to read token file for '{storage_key}': {e}") from e

    def _save_token_data(self, storage_key: str, data: Dict[str, Any]) -> None:
        """Save token data to file.

        Saves both the JSON file (full token data) and a raw token file
        (access token only) for use by non-Python applications.

        Args:
            storage_key: Key to save tokens under
            data: Token data dictionary
        """
        self._ensure_token_dir()
        token_file = self._get_token_file_path(storage_key)
        raw_token_file = self._get_raw_token_file_path(storage_key)

        try:
            # Save JSON file with full token data
            with open(token_file, "w") as f:
                json.dump(data, f, indent=2)
            os.chmod(token_file, 0o600)

            # Save raw token file with access token only (no newline)
            if "access_token" in data:
                with open(raw_token_file, "w") as f:
                    f.write(data["access_token"])
                os.chmod(raw_token_file, 0o600)
        except IOError as e:
            raise StorageError(f"Failed to write token file for '{storage_key}': {e}") from e

    def generate_storage_key(
        self, endpoint: str, realm: str, client_id: str, profile_name: Optional[str] = None
    ) -> str:
        """Generate a storage key for tokens.

        If profile_name is provided, use that as the key.
        Otherwise, generate from endpoint/realm/client_id.

        Args:
            endpoint: OIDC provider endpoint
            realm: Realm or tenant name
            client_id: OAuth2/OIDC client ID
            profile_name: Optional profile name to use as key

        Returns:
            Storage key string
        """
        if profile_name:
            return profile_name

        # Sanitize endpoint for use in key
        # Remove protocol and make filesystem safe
        sanitized_endpoint = endpoint.replace("http://", "").replace("https://", "")
        sanitized_endpoint = re.sub(r"[:/]", "-", sanitized_endpoint)

        # Generate key: endpoint_realm_client
        return f"{sanitized_endpoint}_{realm}_{client_id}"

    def save_tokens(
        self,
        storage_key: str,
        tokens: Dict[str, Any],
        scope: Optional[str] = None,
        expiry_buffer_seconds: int = 300,
    ) -> None:
        """Save tokens to file system.

        Args:
            storage_key: Key to store tokens under
            tokens: Token dictionary from OIDC provider (must contain access_token)
            scope: Optional scope string
            expiry_buffer_seconds: Seconds to subtract from expiry for safety (default: 5 min)

        Raises:
            StorageError: If saving fails
        """
        if "access_token" not in tokens:
            raise StorageError("tokens dictionary must contain 'access_token'")

        # Calculate expiry time
        issued_at = datetime.now(timezone.utc)
        expires_in = tokens.get("expires_in", 3600)  # Default 1 hour

        # Apply buffer but ensure we don't make expiry negative or too short
        # Use min to ensure buffer doesn't exceed 80% of the expiry time
        effective_buffer = min(expiry_buffer_seconds, int(expires_in * 0.8))
        expires_at = issued_at + timedelta(seconds=expires_in - effective_buffer)

        # Prepare token data
        token_data = {
            "access_token": tokens["access_token"],
            "token_type": tokens.get("token_type", "Bearer"),
            "expires_at": expires_at.isoformat(),
            "issued_at": issued_at.isoformat(),
            "scope": scope or tokens.get("scope"),
        }

        # Add optional tokens
        if "refresh_token" in tokens:
            token_data["refresh_token"] = tokens["refresh_token"]

        if "id_token" in tokens:
            token_data["id_token"] = tokens["id_token"]

        # Save to file
        self._save_token_data(storage_key, token_data)

    def get_tokens(self, storage_key: str) -> Dict[str, Any]:
        """Get tokens from file system.

        Args:
            storage_key: Key to retrieve tokens from

        Returns:
            Dictionary containing available tokens

        Raises:
            TokenNotFoundError: If tokens don't exist
            StorageError: If retrieval fails
        """
        token_data = self._load_token_data(storage_key)

        # Validate that required fields exist
        if "access_token" not in token_data:
            raise StorageError(
                f"Token data corrupted for '{storage_key}': missing access_token. "
                f"Run 'oidc token delete {storage_key}' and re-authenticate."
            )

        # Build result with available tokens
        result = {
            "access_token": token_data["access_token"],
            "token_type": token_data.get("token_type", "Bearer"),
        }

        # Add refresh token if available
        if "refresh_token" in token_data:
            result["refresh_token"] = token_data["refresh_token"]

        # Add ID token if available
        if "id_token" in token_data:
            result["id_token"] = token_data["id_token"]

        return result

    def get_metadata(self, storage_key: str) -> Dict[str, Any]:
        """Get token metadata without retrieving actual tokens.

        Args:
            storage_key: Key to get metadata for

        Returns:
            Metadata dictionary

        Raises:
            TokenNotFoundError: If metadata doesn't exist
        """
        token_data = self._load_token_data(storage_key)

        # Return metadata (everything except sensitive tokens)
        return {
            "token_type": token_data.get("token_type", "Bearer"),
            "expires_at": token_data.get("expires_at"),
            "issued_at": token_data.get("issued_at"),
            "scope": token_data.get("scope"),
            "has_refresh_token": "refresh_token" in token_data,
            "has_id_token": "id_token" in token_data,
        }

    def is_expired(self, storage_key: str) -> bool:
        """Check if tokens are expired.

        Args:
            storage_key: Key to check

        Returns:
            True if expired, False if still valid

        Raises:
            TokenNotFoundError: If tokens don't exist
        """
        try:
            metadata = self.get_metadata(storage_key)
            expires_at = datetime.fromisoformat(metadata["expires_at"])
            return datetime.now(timezone.utc) >= expires_at
        except TokenNotFoundError:
            raise

    def get_token_file_path(self, storage_key: str) -> Path:
        """Get the path to the raw token file.

        This file contains only the access token string (no JSON wrapper, no newline),
        suitable for use by non-Python applications that need to read the token directly.

        Note: This method does not check if the token exists or is valid.
        Use token_exists() or is_expired() for validation.

        Args:
            storage_key: Storage key

        Returns:
            Path to the raw token file (.token)

        Example:
            >>> storage = TokenStorage()
            >>> path = storage.get_token_file_path("my-profile")
            >>> print(path)  # ~/.oidc/cache/tokens/my-profile.token
        """
        return self._get_raw_token_file_path(storage_key)

    def delete_tokens(self, storage_key: str) -> None:
        """Delete tokens from file system.

        Deletes both the JSON file and the raw token file.

        Args:
            storage_key: Key to delete

        Raises:
            TokenNotFoundError: If tokens don't exist
        """
        token_file = self._get_token_file_path(storage_key)
        raw_token_file = self._get_raw_token_file_path(storage_key)

        if not token_file.exists():
            raise TokenNotFoundError(f"No tokens found for '{storage_key}'.")

        try:
            token_file.unlink()
            # Also delete raw token file if it exists
            if raw_token_file.exists():
                raw_token_file.unlink()
        except IOError as e:
            raise StorageError(f"Failed to delete token file for '{storage_key}': {e}") from e

    def purge_all_tokens(self) -> int:
        """Delete all tokens from file system.

        Deletes both JSON files and raw token files.

        Returns:
            Number of token sets deleted (counts JSON files)

        Example:
            >>> storage = TokenStorage()
            >>> count = storage.purge_all_tokens()
            >>> print(f"Deleted {count} token(s)")
        """
        if not self.tokens_dir.exists():
            return 0

        count = 0
        try:
            # Delete JSON files and count them
            for token_file in self.tokens_dir.glob("*.json"):
                try:
                    token_file.unlink()
                    count += 1
                except IOError:
                    pass  # Continue deleting other files

            # Also delete raw token files
            for raw_token_file in self.tokens_dir.glob("*.token"):
                try:
                    raw_token_file.unlink()
                except IOError:
                    pass  # Continue deleting other files
        except IOError:
            pass

        return count

    def list_storage_keys(self) -> List[str]:
        """List all storage keys with tokens.

        Returns:
            List of storage keys
        """
        if not self.tokens_dir.exists():
            return []

        storage_keys = []
        for token_file in self.tokens_dir.glob("*.json"):
            # Extract storage key from filename (remove .json extension)
            storage_key = token_file.stem
            # Reverse the sanitization to get original key if needed
            # For now, just use the filename as-is
            storage_keys.append(storage_key)

        return sorted(storage_keys)

    def token_exists(self, storage_key: str) -> bool:
        """Check if tokens exist for a storage key.

        Args:
            storage_key: Key to check

        Returns:
            True if tokens exist, False otherwise
        """
        token_file = self._get_token_file_path(storage_key)
        return token_file.exists()
