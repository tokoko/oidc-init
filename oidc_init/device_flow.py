"""Device Authorization Grant flow (RFC 8628) implementation."""

import time
from typing import Any, Dict, Optional
import requests


class DeviceFlowError(Exception):
    """Base exception for device flow errors."""

    pass


class DeviceFlowTimeout(DeviceFlowError):
    """Raised when the device code expires before user authorization."""

    pass


class DeviceFlowDenied(DeviceFlowError):
    """Raised when the user denies the authorization request."""

    pass


def initiate_device_flow(
    token_endpoint: str,
    client_id: str,
    client_secret: Optional[str] = None,
    scope: Optional[str] = None,
    timeout: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Initiate OAuth2 Device Authorization Grant flow and poll until completion.

    This function implements the device code flow (RFC 8628):
    1. Requests device and user codes from the authorization server
    2. Displays verification URI and user code to the user
    3. Polls the token endpoint until the user completes authorization
    4. Returns the tokens upon successful authorization

    Args:
        token_endpoint: The OIDC provider's token endpoint URL.
                       Device authorization endpoint is derived by replacing
                       '/token' with '/auth/device'.
        client_id: The OAuth2 client ID
        client_secret: Optional client secret for confidential clients
        scope: Optional space-separated list of scopes to request
        timeout: Optional custom timeout in seconds (overrides server's expires_in)

    Returns:
        Dictionary containing:
        - access_token: The access token
        - token_type: Token type (usually "Bearer")
        - expires_in: Token expiration time in seconds
        - refresh_token: Refresh token (if available)
        - scope: Granted scopes (if available)
        - id_token: ID token (if OIDC scope was requested)

    Raises:
        DeviceFlowTimeout: If the device code expires before authorization
        DeviceFlowDenied: If the user denies the authorization
        DeviceFlowError: For other authorization errors
        requests.RequestException: For network/HTTP errors

    Example:
        >>> tokens = initiate_device_flow(
        ...     token_endpoint="https://provider.com/realms/my-realm/protocol/openid-connect/token",
        ...     client_id="my-client",
        ...     scope="openid profile email"
        ... )
        >>> print(f"Access token: {tokens['access_token']}")
    """
    # Derive device authorization endpoint from token endpoint
    # Standard pattern: /token -> /auth/device
    device_auth_endpoint = token_endpoint.replace("/token", "/auth/device")

    # Step 1: Request device and user codes
    device_auth_data = {"client_id": client_id}
    if scope:
        device_auth_data["scope"] = scope

    print(f"Requesting device code from {device_auth_endpoint}...")
    try:
        device_response = requests.post(device_auth_endpoint, data=device_auth_data, timeout=30)
        device_response.raise_for_status()
    except requests.RequestException as e:
        raise DeviceFlowError(f"Failed to request device code: {e}") from e

    device_data = device_response.json()

    # Extract required fields
    device_code = device_data.get("device_code")
    user_code = device_data.get("user_code")
    verification_uri = device_data.get("verification_uri")
    verification_uri_complete = device_data.get("verification_uri_complete")
    expires_in = device_data.get("expires_in", 300)  # Default 5 minutes
    interval = device_data.get("interval", 5)  # Default 5 seconds

    if not all([device_code, user_code, verification_uri]):
        raise DeviceFlowError(
            f"Invalid device authorization response: missing required fields. "
            f"Response: {device_data}"
        )

    # Step 2: Display instructions to the user
    print("\n" + "=" * 70)
    print("DEVICE AUTHORIZATION REQUIRED")
    print("=" * 70)
    if verification_uri_complete:
        print(f"\nOpen this URL in your browser:\n  {verification_uri_complete}")
    else:
        print(f"\n1. Open this URL in your browser:\n   {verification_uri}")
        print(f"\n2. Enter this code:\n   {user_code}")
    print("\n" + "=" * 70)
    print("\nWaiting for authorization", end="", flush=True)

    # Step 3: Poll the token endpoint
    start_time = time.time()
    effective_timeout = timeout if timeout is not None else expires_in

    while True:
        # Check timeout
        elapsed = time.time() - start_time
        if elapsed > effective_timeout:
            raise DeviceFlowTimeout(
                f"Device code expired after {effective_timeout} seconds without authorization"
            )

        # Wait before polling (respect interval)
        time.sleep(interval)

        # Poll token endpoint
        token_data: Dict[str, Any] = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "client_id": client_id,
        }
        if client_secret:
            token_data["client_secret"] = client_secret

        try:
            token_response = requests.post(token_endpoint, data=token_data, timeout=30)
        except requests.RequestException:
            # Network error, continue polling
            print("!", end="", flush=True)
            continue

        # Success!
        if token_response.status_code == 200:
            print("\n\nAuthorization successful!")
            return token_response.json()

        # Handle errors
        try:
            error_data = token_response.json()
            error_code = error_data.get("error", "unknown_error")
            error_description = error_data.get("error_description", "")
        except ValueError:
            # Response is not JSON
            error_code = "unknown_error"
            error_description = token_response.text

        if error_code == "authorization_pending":
            # User hasn't completed authorization yet, keep polling
            print(".", end="", flush=True)
            continue
        elif error_code == "slow_down":
            # We're polling too fast, increase interval by 5 seconds (per RFC 8628)
            interval += 5
            print(".", end="", flush=True)
            continue
        elif error_code == "access_denied":
            # User explicitly denied the request
            raise DeviceFlowDenied(f"Authorization denied by user: {error_description}")
        elif error_code == "expired_token":
            # Device code expired
            raise DeviceFlowTimeout(f"Device code expired: {error_description}")
        else:
            # Other error
            raise DeviceFlowError(
                f"Authorization failed: {error_code} - {error_description}"
            )
