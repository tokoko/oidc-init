"""Core authentication logic for OIDC initialization."""

from typing import Optional, Dict, Any
from .device_flow import initiate_device_flow
from .profiles import ProfileManager
from .storage import TokenStorage


class AuthenticationError(Exception):
    """Base exception for authentication errors."""

    pass


def run_init(
    profile: Optional[str] = None,
    endpoint: Optional[str] = None,
    realm: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    scope: Optional[str] = None,
    flow: Optional[str] = None,
    protocol: Optional[str] = None,
    verify: bool = True,
    timeout: Optional[int] = None,
    save_profile: Optional[str] = None,
    silent: bool = False,
) -> Dict[str, Any]:
    """Run OIDC initialization flow and store tokens.

    This function handles the complete authentication flow:
    1. Loads profile configuration (if specified)
    2. Merges with any explicit parameters
    3. Runs the device flow authentication
    4. Saves tokens to storage
    5. Optionally saves the profile configuration

    Args:
        profile: Profile name to use (loads configuration from saved profile)
        endpoint: OIDC provider endpoint (overrides profile)
        realm: Realm or tenant name (overrides profile)
        client_id: OAuth2/OIDC client ID (overrides profile)
        client_secret: Optional client secret (overrides profile)
        scope: Space-separated list of scopes (overrides profile)
        flow: Authentication flow (default: "device")
        protocol: Protocol to use (http/https, default: "https")
        verify: Whether to verify SSL certificates (default: True)
        timeout: Optional custom timeout in seconds
        save_profile: Optional profile name to save this configuration
        silent: If True, suppress informational messages (errors still raised)

    Returns:
        Dictionary containing the result with keys:
        - storage_key: Where the tokens were stored
        - tokens: The token dictionary from the provider

    Raises:
        AuthenticationError: If authentication fails
        ProfileNotFoundError: If specified profile doesn't exist
        DeviceFlowError: If device flow fails
        StorageError: If token storage fails
    """
    profile_manager = ProfileManager()
    config: Dict[str, Any] = {}

    # Determine which profile to use
    profile_to_use = profile
    if not profile_to_use:
        # Check if there's a default profile
        default_profile = profile_manager.get_default_profile()
        if default_profile:
            profile_to_use = default_profile
            if not silent:
                print(f"Using default profile: {default_profile}")

    # Load profile configuration
    if profile_to_use:
        config = profile_manager.get_profile(profile_to_use)
        if profile and not silent:  # Only show if user explicitly specified --profile
            print(f"Using profile: {profile}")

    # Override profile settings with explicit parameters
    if endpoint is not None:
        config["endpoint"] = endpoint
    if realm is not None:
        config["realm"] = realm
    if client_id is not None:
        config["client_id"] = client_id
    if client_secret is not None:
        config["client_secret"] = client_secret
    if scope is not None:
        config["scope"] = scope
    if flow is not None:
        config["flow"] = flow
    if protocol is not None:
        config["protocol"] = protocol
    if not verify:
        config["verify"] = False

    # Apply defaults
    config.setdefault("scope", "openid profile email")
    config.setdefault("flow", "device")
    config.setdefault("protocol", "https")
    config.setdefault("client_secret", None)
    config.setdefault("verify", True)

    # Validate required parameters
    required = ["endpoint", "realm", "client_id"]
    missing = [param for param in required if param not in config or config[param] is None]
    if missing:
        raise AuthenticationError(
            f"Missing required parameters: {', '.join(missing)}. "
            f"Either specify them explicitly or use a saved profile."
        )

    # Extract final values
    final_endpoint = config["endpoint"]
    final_realm = config["realm"]
    final_client_id = config["client_id"]
    final_client_secret = config.get("client_secret")
    final_scope = config["scope"]
    final_flow = config["flow"]
    final_protocol = config["protocol"]
    final_verify = config["verify"]

    # Construct the full token endpoint URL
    token_endpoint = _build_token_endpoint(final_endpoint, final_realm, final_protocol)

    if not silent:
        print(f"Initiating {final_flow} flow authentication...")
        print(f"Endpoint: {token_endpoint}")
        print(f"Client ID: {final_client_id}")
        print(f"Scopes: {final_scope}")

    # Run device flow
    if final_flow == "device":
        tokens = initiate_device_flow(
            token_endpoint=token_endpoint,
            client_id=final_client_id,
            client_secret=final_client_secret,
            scope=final_scope,
            timeout=timeout,
            verify=final_verify,
        )

        if not silent:
            # Display token information
            print("\n" + "=" * 70)
            print("TOKENS RECEIVED")
            print("=" * 70)
            print(f"Access Token: {tokens['access_token'][:50]}...")
            print(f"Token Type: {tokens['token_type']}")
            print(f"Expires In: {tokens['expires_in']} seconds")

            if "refresh_token" in tokens:
                print(f"Refresh Token: {tokens['refresh_token'][:50]}...")

            if "id_token" in tokens:
                print(f"ID Token: {tokens['id_token'][:50]}...")

            if "scope" in tokens:
                print(f"Granted Scopes: {tokens['scope']}")

            print("=" * 70)

        # Save profile if requested
        if save_profile:
            from .profiles import ProfileExistsError

            try:
                profile_manager.add_profile(
                    name=save_profile,
                    endpoint=final_endpoint,
                    realm=final_realm,
                    client_id=final_client_id,
                    client_secret=final_client_secret,
                    scope=final_scope,
                    protocol=final_protocol,
                    flow=final_flow,
                    verify=final_verify,
                    overwrite=False,
                )
                if not silent:
                    print(f"\nProfile '{save_profile}' saved to ~/.oidc/profiles.json")
            except ProfileExistsError:
                if not silent:
                    print(
                        f"\nWarning: Profile '{save_profile}' already exists. "
                        f"Use 'oidc profile delete {save_profile}' first to replace it."
                    )

        # Store tokens
        token_storage = TokenStorage()

        # Determine storage key (use profile name if available, or auto-generate)
        storage_key = token_storage.generate_storage_key(
            endpoint=final_endpoint,
            realm=final_realm,
            client_id=final_client_id,
            profile_name=profile_to_use or save_profile,
        )

        token_storage.save_tokens(
            storage_key=storage_key,
            tokens=tokens,
            scope=final_scope,
        )

        if not silent:
            print("\nTokens stored securely.")
            print(f"Storage key: {storage_key}")

            # Show helpful message about auto-generated keys
            if not profile_to_use and not save_profile:
                print(
                    "\nNote: Tokens stored with auto-generated key. "
                    "Use 'oidc token list' to view all stored tokens."
                )

        return {"storage_key": storage_key, "tokens": tokens}

    else:
        raise AuthenticationError(f"Flow '{final_flow}' is not yet implemented.")


def _build_token_endpoint(endpoint: str, realm: str, protocol: str) -> str:
    """Build the OIDC token endpoint URL from components.

    Args:
        endpoint: Host and optional port (e.g., 'keycloak:8080' or 'https://provider.com')
        realm: Realm/tenant name
        protocol: Protocol to use if not in endpoint ('http' or 'https')

    Returns:
        Full token endpoint URL
    """
    # Check if endpoint already has a protocol
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        base_url = endpoint.rstrip("/")
    else:
        base_url = f"{protocol}://{endpoint}"

    # Construct Keycloak-style OIDC endpoint
    # TODO: Support other providers (detect provider type or make configurable)
    return f"{base_url}/realms/{realm}/protocol/openid-connect/token"
