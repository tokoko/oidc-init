"""oidc-init: CLI tool and Python SDK for obtaining and caching OIDC tokens.

Example usage:

    # Get access token from default profile
    from oidc_init import get_token
    token = get_token()

    # Get access token from specific profile/storage key
    token = get_token("my-keycloak")

    # Get all tokens (access, refresh, id)
    from oidc_init import get_tokens
    tokens = get_tokens("my-keycloak")
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # Search for available tokens
    from oidc_init import list_tokens
    available = list_tokens()
    print(f"Available tokens: {available}")
"""

__version__ = "0.1.0"

from .storage import TokenStorage, TokenNotFoundError, StorageError
from .profiles import ProfileManager, ProfileNotFoundError, ProfileError
from typing import Dict, List, Optional, Any


def get_token(storage_key: Optional[str] = None) -> str:
    """Get an access token from storage.

    Args:
        storage_key: Storage key or profile name. If None, uses default profile.

    Returns:
        The access token string

    Raises:
        TokenNotFoundError: If token doesn't exist or is expired
        ProfileNotFoundError: If no storage key provided and no default profile set
        StorageError: If retrieval fails

    Example:
        >>> import requests
        >>> from oidc_init import get_token
        >>> token = get_token("my-keycloak")
        >>> response = requests.get(
        ...     "https://api.example.com/data",
        ...     headers={"Authorization": f"Bearer {token}"}
        ... )
    """
    token_storage = TokenStorage()

    # Determine storage key
    final_key = storage_key
    if not final_key:
        # Try to use default profile
        profile_manager = ProfileManager()
        default_profile = profile_manager.get_default_profile()
        if default_profile:
            final_key = default_profile
        else:
            raise ProfileNotFoundError(
                "No storage key provided and no default profile set. "
                "Either specify a storage key or set a default profile with 'oidc profile set-default'."
            )

    # Check if expired
    if token_storage.is_expired(final_key):
        raise TokenNotFoundError(
            f"Token for '{final_key}' has expired. "
            f"Run 'oidc init --profile {final_key}' to re-authenticate."
        )

    # Get tokens and return access token
    tokens = token_storage.get_tokens(final_key)
    return tokens["access_token"]


def get_tokens(storage_key: Optional[str] = None) -> Dict[str, Any]:
    """Get all tokens (access, refresh, id) from storage.

    Args:
        storage_key: Storage key or profile name. If None, uses default profile.

    Returns:
        Dictionary containing:
        - access_token: The access token
        - token_type: Token type (usually "Bearer")
        - refresh_token: Refresh token (if available)
        - id_token: ID token (if available)

    Raises:
        TokenNotFoundError: If token doesn't exist or is expired
        ProfileNotFoundError: If no storage key provided and no default profile set
        StorageError: If retrieval fails

    Example:
        >>> from oidc_init import get_tokens
        >>> tokens = get_tokens("my-keycloak")
        >>> print(f"Access token: {tokens['access_token'][:20]}...")
        >>> if 'refresh_token' in tokens:
        ...     print("Refresh token available")
    """
    token_storage = TokenStorage()

    # Determine storage key
    final_key = storage_key
    if not final_key:
        profile_manager = ProfileManager()
        default_profile = profile_manager.get_default_profile()
        if default_profile:
            final_key = default_profile
        else:
            raise ProfileNotFoundError(
                "No storage key provided and no default profile set. "
                "Either specify a storage key or set a default profile with 'oidc profile set-default'."
            )

    # Check if expired
    if token_storage.is_expired(final_key):
        raise TokenNotFoundError(
            f"Token for '{final_key}' has expired. "
            f"Run 'oidc init --profile {final_key}' to re-authenticate."
        )

    return token_storage.get_tokens(final_key)


def list_tokens(include_expired: bool = False) -> List[str]:
    """List all available token storage keys.

    Args:
        include_expired: If True, include expired tokens in the list

    Returns:
        List of storage keys

    Example:
        >>> from oidc_init import list_tokens
        >>> keys = list_tokens()
        >>> print(f"Available tokens: {keys}")
        >>> for key in keys:
        ...     token = get_token(key)
        ...     # Use token...
    """
    token_storage = TokenStorage()
    all_keys = token_storage.list_storage_keys()

    if include_expired:
        return all_keys

    # Filter out expired tokens
    valid_keys = []
    for key in all_keys:
        try:
            if not token_storage.is_expired(key):
                valid_keys.append(key)
        except Exception:
            # Skip tokens that have issues
            continue

    return valid_keys


def is_token_valid(storage_key: str) -> bool:
    """Check if a token exists and is still valid (not expired).

    Args:
        storage_key: Storage key or profile name to check

    Returns:
        True if token exists and is valid, False otherwise

    Example:
        >>> from oidc_init import is_token_valid
        >>> if is_token_valid("my-keycloak"):
        ...     token = get_token("my-keycloak")
        ... else:
        ...     print("Token expired, please re-authenticate")
    """
    token_storage = TokenStorage()

    try:
        return not token_storage.is_expired(storage_key)
    except TokenNotFoundError:
        return False


def purge_tokens() -> int:
    """Delete all stored tokens.

    Use with caution - this removes ALL tokens from storage!

    Returns:
        Number of tokens deleted

    Example:
        >>> from oidc_init import purge_tokens
        >>> count = purge_tokens()
        >>> print(f"Deleted {count} token(s)")
    """
    token_storage = TokenStorage()
    return token_storage.purge_all_tokens()


# Public API exports
__all__ = [
    "__version__",
    "get_token",
    "get_tokens",
    "list_tokens",
    "is_token_valid",
    "purge_tokens",
    "TokenStorage",
    "ProfileManager",
    "TokenNotFoundError",
    "ProfileNotFoundError",
    "StorageError",
    "ProfileError",
]
