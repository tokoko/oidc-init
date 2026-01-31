"""oidc-init Python SDK -- thin wrapper around the Go CLI and token files.

Example::

    from oidc_init import get_token
    token = get_token("my-keycloak")
"""

__version__ = "0.1.0"

from typing import Any, Dict, List, Optional

from .cli import AuthenticationError, CLINotFoundError
from .cli import run_init as _run_init
from .reader import StorageError, TokenNotFoundError
from .reader import delete_token_files as _delete_token_files
from .reader import is_expired as _is_expired
from .reader import list_keys as _list_keys
from .reader import purge_all as _purge_all
from .reader import read_token_data
from .reader import token_file_path as _token_file_path


class ProfileNotFoundError(Exception):
    """Raised when no profile/storage_key can be determined."""

    pass


def _resolve_key(storage_key: Optional[str]) -> str:
    """Resolve storage key: use provided key, or fall back to default profile.

    Reads ``~/.oidc/profiles.json`` to find the ``_default`` key.
    """
    if storage_key:
        return storage_key

    import json
    from pathlib import Path

    profiles_file = Path.home() / ".oidc" / "profiles.json"
    if profiles_file.exists():
        try:
            with open(profiles_file, "r") as f:
                profiles = json.load(f)
            default = profiles.get("_default")
            if default and isinstance(default, str):
                return default
        except (json.JSONDecodeError, IOError):
            pass

    raise ProfileNotFoundError(
        "No storage key provided and no default profile set. "
        "Either specify a storage key or set a default profile with "
        "'oidc profile set-default'."
    )


def _ensure_valid_token(final_key: str) -> None:
    """Check if token is valid; if expired or missing, trigger re-auth via CLI."""
    try:
        if _is_expired(final_key):
            _run_init(profile=final_key)
    except TokenNotFoundError:
        _run_init(profile=final_key)


def get_token(storage_key: Optional[str] = None) -> str:
    """Get an access token, auto-reauthenticating via CLI if expired.

    Args:
        storage_key: Profile name or storage key. Uses default profile if None.

    Returns:
        The access token string.
    """
    final_key = _resolve_key(storage_key)
    _ensure_valid_token(final_key)
    data = read_token_data(final_key)
    return data["access_token"]


def get_tokens(storage_key: Optional[str] = None) -> Dict[str, Any]:
    """Get all tokens (access, refresh, id), auto-reauthenticating if expired.

    Returns dict with: access_token, token_type, and optionally
    refresh_token, id_token.
    """
    final_key = _resolve_key(storage_key)
    _ensure_valid_token(final_key)
    data = read_token_data(final_key)
    result: Dict[str, Any] = {
        "access_token": data["access_token"],
        "token_type": data.get("token_type", "Bearer"),
    }
    if "refresh_token" in data:
        result["refresh_token"] = data["refresh_token"]
    if "id_token" in data:
        result["id_token"] = data["id_token"]
    return result


def get_token_path(storage_key: Optional[str] = None) -> str:
    """Get path to .token file, auto-reauthenticating if expired.

    Returns the absolute path string to the raw access token file.
    """
    final_key = _resolve_key(storage_key)
    _ensure_valid_token(final_key)
    return _token_file_path(final_key)


def list_tokens(include_expired: bool = False) -> List[str]:
    """List all available token storage keys.

    Args:
        include_expired: If True, include expired tokens.
    """
    all_keys = _list_keys()
    if include_expired:
        return all_keys
    valid: List[str] = []
    for key in all_keys:
        try:
            if not _is_expired(key):
                valid.append(key)
        except Exception:
            continue
    return valid


def is_token_valid(storage_key: str) -> bool:
    """Check if a token exists and has not expired."""
    try:
        return not _is_expired(storage_key)
    except TokenNotFoundError:
        return False


def purge_tokens() -> int:
    """Delete all stored tokens. Returns count deleted."""
    return _purge_all()


__all__ = [
    "__version__",
    "get_token",
    "get_tokens",
    "get_token_path",
    "list_tokens",
    "is_token_valid",
    "purge_tokens",
    "read_token_data",
    "TokenNotFoundError",
    "ProfileNotFoundError",
    "StorageError",
    "AuthenticationError",
    "CLINotFoundError",
]
