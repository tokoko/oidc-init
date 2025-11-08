"""Token storage management using OS keyring and metadata file."""

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List
import keyring
from keyring.backends.fail import Keyring as FailKeyring


class StorageError(Exception):
    """Base exception for storage-related errors."""

    pass


class TokenNotFoundError(StorageError):
    """Raised when a token doesn't exist."""

    pass


# Default token storage directory
DEFAULT_TOKEN_DIR = Path.home() / ".oidc"
DEFAULT_TOKEN_FILE = DEFAULT_TOKEN_DIR / "tokens.json"

# Keyring service name
KEYRING_SERVICE = "oidc"


def _setup_keyring() -> None:
    """Set up keyring backend, falling back to encrypted file if needed."""
    current_backend = keyring.get_keyring()

    # Check if the current backend is the fail backend (no recommended backend available)
    if isinstance(current_backend, FailKeyring):
        try:
            # Try to use the encrypted file backend from keyrings.alt
            from keyrings.alt.file import EncryptedKeyring

            # Set keyring file location in .oidc directory
            keyring_file = DEFAULT_TOKEN_DIR / "keyring.cfg"
            encrypted_keyring = EncryptedKeyring()
            encrypted_keyring.file_path = str(keyring_file)

            keyring.set_keyring(encrypted_keyring)
        except ImportError:
            # If keyrings.alt is not available, raise an error
            raise StorageError(
                "No keyring backend available and keyrings.alt is not installed. "
                "Install keyrings.alt: pip install keyrings.alt"
            )


# Set up keyring on module import
_setup_keyring()


class TokenStorage:
    """Manage OIDC token storage in OS keyring with metadata."""

    def __init__(self, token_file: Optional[Path] = None):
        """Initialize the token storage.

        Args:
            token_file: Path to the tokens.json metadata file (default: ~/.oidc/tokens.json)
        """
        self.token_file = token_file or DEFAULT_TOKEN_FILE

    def _ensure_token_dir(self) -> None:
        """Ensure the token directory exists."""
        self.token_file.parent.mkdir(parents=True, exist_ok=True)

    def _load_metadata(self) -> Dict[str, Dict[str, Any]]:
        """Load token metadata from the file.

        Returns:
            Dictionary of storage_key -> metadata
        """
        if not self.token_file.exists():
            return {}

        try:
            with open(self.token_file, "r") as f:
                metadata = json.load(f)
                if not isinstance(metadata, dict):
                    raise StorageError(
                        f"Invalid tokens file format: expected dict, got {type(metadata)}"
                    )
                return metadata
        except json.JSONDecodeError as e:
            raise StorageError(f"Failed to parse tokens file: {e}") from e
        except IOError as e:
            raise StorageError(f"Failed to read tokens file: {e}") from e

    def _save_metadata(self, metadata: Dict[str, Dict[str, Any]]) -> None:
        """Save token metadata to the file.

        Args:
            metadata: Dictionary of storage_key -> metadata
        """
        self._ensure_token_dir()

        try:
            with open(self.token_file, "w") as f:
                json.dump(metadata, f, indent=2)
        except IOError as e:
            raise StorageError(f"Failed to write tokens file: {e}") from e

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
        # Remove protocol and make filesystem/keyring safe
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
        """Save tokens to keyring and metadata.

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

        # Store tokens in keyring
        access_token = tokens["access_token"]
        refresh_token = tokens.get("refresh_token")
        id_token = tokens.get("id_token")

        try:
            keyring.set_password(KEYRING_SERVICE, f"{storage_key}:access_token", access_token)

            if refresh_token:
                keyring.set_password(
                    KEYRING_SERVICE, f"{storage_key}:refresh_token", refresh_token
                )

            if id_token:
                keyring.set_password(KEYRING_SERVICE, f"{storage_key}:id_token", id_token)

        except Exception as e:
            raise StorageError(f"Failed to store tokens in keyring: {e}") from e

        # Calculate expiry time
        issued_at = datetime.now(timezone.utc)
        expires_in = tokens.get("expires_in", 3600)  # Default 1 hour

        # Apply buffer but ensure we don't make expiry negative or too short
        # Use min to ensure buffer doesn't exceed 80% of the expiry time
        effective_buffer = min(expiry_buffer_seconds, int(expires_in * 0.8))
        expires_at = issued_at + timedelta(seconds=expires_in - effective_buffer)

        # Store metadata
        metadata = self._load_metadata()
        metadata[storage_key] = {
            "token_type": tokens.get("token_type", "Bearer"),
            "expires_at": expires_at.isoformat(),
            "issued_at": issued_at.isoformat(),
            "scope": scope or tokens.get("scope"),
            "has_refresh_token": refresh_token is not None,
            "has_id_token": id_token is not None,
        }
        self._save_metadata(metadata)

    def get_tokens(self, storage_key: str) -> Dict[str, Any]:
        """Get tokens from keyring.

        Args:
            storage_key: Key to retrieve tokens from

        Returns:
            Dictionary containing available tokens

        Raises:
            TokenNotFoundError: If tokens don't exist
            StorageError: If retrieval fails
        """
        metadata = self._load_metadata()

        if storage_key not in metadata:
            raise TokenNotFoundError(
                f"No tokens found for '{storage_key}'. Run 'oidc init' to authenticate."
            )

        try:
            # Retrieve tokens from keyring
            access_token = keyring.get_password(KEYRING_SERVICE, f"{storage_key}:access_token")

            if not access_token:
                # Metadata exists but token is missing from keyring
                raise TokenNotFoundError(
                    f"Token data corrupted for '{storage_key}'. "
                    f"Run 'oidc token delete {storage_key}' and re-authenticate."
                )

            result = {
                "access_token": access_token,
                "token_type": metadata[storage_key]["token_type"],
            }

            # Add refresh token if available
            if metadata[storage_key].get("has_refresh_token"):
                refresh_token = keyring.get_password(
                    KEYRING_SERVICE, f"{storage_key}:refresh_token"
                )
                if refresh_token:
                    result["refresh_token"] = refresh_token

            # Add ID token if available
            if metadata[storage_key].get("has_id_token"):
                id_token = keyring.get_password(KEYRING_SERVICE, f"{storage_key}:id_token")
                if id_token:
                    result["id_token"] = id_token

            return result

        except Exception as e:
            if isinstance(e, TokenNotFoundError):
                raise
            raise StorageError(f"Failed to retrieve tokens from keyring: {e}") from e

    def get_metadata(self, storage_key: str) -> Dict[str, Any]:
        """Get token metadata without retrieving actual tokens.

        Args:
            storage_key: Key to get metadata for

        Returns:
            Metadata dictionary

        Raises:
            TokenNotFoundError: If metadata doesn't exist
        """
        metadata = self._load_metadata()

        if storage_key not in metadata:
            raise TokenNotFoundError(f"No tokens found for '{storage_key}'.")

        return metadata[storage_key]

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

    def delete_tokens(self, storage_key: str) -> None:
        """Delete tokens from keyring and metadata.

        Args:
            storage_key: Key to delete

        Raises:
            TokenNotFoundError: If tokens don't exist
        """
        metadata = self._load_metadata()

        if storage_key not in metadata:
            raise TokenNotFoundError(f"No tokens found for '{storage_key}'.")

        # Delete from keyring
        try:
            keyring.delete_password(KEYRING_SERVICE, f"{storage_key}:access_token")
        except keyring.errors.PasswordDeleteError:
            pass  # Already deleted

        try:
            keyring.delete_password(KEYRING_SERVICE, f"{storage_key}:refresh_token")
        except keyring.errors.PasswordDeleteError:
            pass  # Already deleted

        try:
            keyring.delete_password(KEYRING_SERVICE, f"{storage_key}:id_token")
        except keyring.errors.PasswordDeleteError:
            pass  # Already deleted

        # Delete metadata
        del metadata[storage_key]
        self._save_metadata(metadata)

    def purge_all_tokens(self) -> int:
        """Delete all tokens from keyring and metadata.

        Returns:
            Number of tokens deleted

        Example:
            >>> storage = TokenStorage()
            >>> count = storage.purge_all_tokens()
            >>> print(f"Deleted {count} token(s)")
        """
        metadata = self._load_metadata()
        storage_keys = list(metadata.keys())

        # Delete all tokens from keyring
        for storage_key in storage_keys:
            try:
                keyring.delete_password(KEYRING_SERVICE, f"{storage_key}:access_token")
            except keyring.errors.PasswordDeleteError:
                pass

            try:
                keyring.delete_password(KEYRING_SERVICE, f"{storage_key}:refresh_token")
            except keyring.errors.PasswordDeleteError:
                pass

            try:
                keyring.delete_password(KEYRING_SERVICE, f"{storage_key}:id_token")
            except keyring.errors.PasswordDeleteError:
                pass

        # Clear metadata file
        self._save_metadata({})

        return len(storage_keys)

    def list_storage_keys(self) -> List[str]:
        """List all storage keys with tokens.

        Returns:
            List of storage keys
        """
        metadata = self._load_metadata()
        return sorted(metadata.keys())

    def token_exists(self, storage_key: str) -> bool:
        """Check if tokens exist for a storage key.

        Args:
            storage_key: Key to check

        Returns:
            True if tokens exist, False otherwise
        """
        metadata = self._load_metadata()
        return storage_key in metadata
