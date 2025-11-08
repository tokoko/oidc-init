#!/usr/bin/env python3
"""
Helper script to create a Keycloak realm and client with device code auth flow enabled.

Usage:
    python scripts/setup_keycloak.py --realm my-realm --client my-client

Requirements:
    - Keycloak running on keycloak:8080
    - Admin credentials: admin/admin (default)
"""

import argparse
import sys
import time
from typing import Dict, Any, Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class KeycloakSetup:
    """Helper class for setting up Keycloak realm and clients."""

    def __init__(
        self,
        base_url: str = "http://keycloak:8080",
        admin_user: str = "admin",
        admin_password: str = "admin",
    ):
        self.base_url = base_url.rstrip("/")
        self.admin_user = admin_user
        self.admin_password = admin_password
        self.access_token: Optional[str] = None
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create a requests session with retry logic."""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def authenticate(self) -> None:
        """Authenticate with Keycloak admin API and get access token."""
        url = f"{self.base_url}/realms/master/protocol/openid-connect/token"
        data = {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": self.admin_user,
            "password": self.admin_password,
        }

        print(f"Authenticating with Keycloak at {self.base_url}...")
        try:
            response = self.session.post(url, data=data, timeout=10)
            response.raise_for_status()
            self.access_token = response.json()["access_token"]
            print("Authentication successful!")
        except requests.exceptions.ConnectionError:
            print(f"Error: Could not connect to Keycloak at {self.base_url}")
            print("Make sure Keycloak is running (default: keycloak:8080)")
            sys.exit(1)
        except requests.exceptions.HTTPError as e:
            print(f"Authentication failed: {e}")
            print(f"Response: {response.text}")
            sys.exit(1)

    def _get_headers(self) -> Dict[str, str]:
        """Get headers with authentication token."""
        if not self.access_token:
            raise ValueError("Not authenticated. Call authenticate() first.")
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }

    def realm_exists(self, realm_name: str) -> bool:
        """Check if a realm already exists."""
        url = f"{self.base_url}/admin/realms/{realm_name}"
        try:
            response = self.session.get(url, headers=self._get_headers(), timeout=10)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def create_realm(self, realm_name: str, display_name: Optional[str] = None) -> None:
        """Create a new realm in Keycloak."""
        if self.realm_exists(realm_name):
            print(f"Realm '{realm_name}' already exists, skipping creation.")
            return

        url = f"{self.base_url}/admin/realms"
        realm_data = {
            "realm": realm_name,
            "displayName": display_name or realm_name,
            "enabled": True,
            "sslRequired": "none",  # For local development
            "registrationAllowed": False,
            "loginWithEmailAllowed": True,
            "duplicateEmailsAllowed": False,
            "resetPasswordAllowed": True,
            "editUsernameAllowed": False,
            "bruteForceProtected": True,
        }

        print(f"Creating realm '{realm_name}'...")
        try:
            response = self.session.post(
                url, json=realm_data, headers=self._get_headers(), timeout=10
            )
            response.raise_for_status()
            print(f"Realm '{realm_name}' created successfully!")
        except requests.exceptions.HTTPError as e:
            print(f"Failed to create realm: {e}")
            print(f"Response: {response.text}")
            sys.exit(1)

    def client_exists(self, realm_name: str, client_id: str) -> bool:
        """Check if a client already exists in a realm."""
        url = f"{self.base_url}/admin/realms/{realm_name}/clients"
        try:
            response = self.session.get(url, headers=self._get_headers(), timeout=10)
            response.raise_for_status()
            clients = response.json()
            return any(client["clientId"] == client_id for client in clients)
        except requests.exceptions.RequestException:
            return False

    def create_client(
        self,
        realm_name: str,
        client_id: str,
        client_name: Optional[str] = None,
        public: bool = True,
    ) -> Dict[str, Any]:
        """
        Create a new client with device authorization grant flow enabled.

        Args:
            realm_name: The realm to create the client in
            client_id: The client ID
            client_name: Display name for the client (optional)
            public: Whether this is a public client (True) or confidential (False)

        Returns:
            Dictionary with client configuration including client_id and secret (if confidential)
        """
        if self.client_exists(realm_name, client_id):
            print(f"Client '{client_id}' already exists in realm '{realm_name}', skipping creation.")
            return {"client_id": client_id, "exists": True}

        url = f"{self.base_url}/admin/realms/{realm_name}/clients"

        # Client configuration with device flow enabled
        client_data = {
            "clientId": client_id,
            "name": client_name or client_id,
            "enabled": True,
            "publicClient": public,
            "standardFlowEnabled": True,  # Authorization Code Flow
            "directAccessGrantsEnabled": True,  # Direct Access Grants (Resource Owner Password)
            "serviceAccountsEnabled": not public,  # Service accounts for confidential clients
            "authorizationServicesEnabled": False,
            "protocol": "openid-connect",
            "attributes": {
                "oauth2.device.authorization.grant.enabled": "true",  # Enable device flow
                "oidc.ciba.grant.enabled": "false",
                "backchannel.logout.session.required": "true",
                "backchannel.logout.revoke.offline.tokens": "false",
            },
            "redirectUris": ["http://localhost:*"],
            "webOrigins": ["+"],
            "defaultClientScopes": ["web-origins", "profile", "roles", "email"],
            "optionalClientScopes": ["address", "phone", "offline_access", "microprofile-jwt"],
        }

        print(f"Creating client '{client_id}' in realm '{realm_name}'...")
        print(f"  - Public client: {public}")
        print(f"  - Device authorization grant: enabled")

        try:
            response = self.session.post(
                url, json=client_data, headers=self._get_headers(), timeout=10
            )
            response.raise_for_status()
            print(f"Client '{client_id}' created successfully!")

            result = {"client_id": client_id, "realm": realm_name, "public": public}

            # Get the client secret if it's a confidential client
            if not public:
                secret = self._get_client_secret(realm_name, client_id)
                if secret:
                    result["client_secret"] = secret

            return result

        except requests.exceptions.HTTPError as e:
            print(f"Failed to create client: {e}")
            print(f"Response: {response.text}")
            sys.exit(1)

    def _get_client_secret(self, realm_name: str, client_id: str) -> Optional[str]:
        """Get the client secret for a confidential client."""
        # First, get the internal client UUID
        url = f"{self.base_url}/admin/realms/{realm_name}/clients"
        params = {"clientId": client_id}

        try:
            response = self.session.get(
                url, params=params, headers=self._get_headers(), timeout=10
            )
            response.raise_for_status()
            clients = response.json()

            if not clients:
                return None

            client_uuid = clients[0]["id"]

            # Get the client secret
            secret_url = f"{self.base_url}/admin/realms/{realm_name}/clients/{client_uuid}/client-secret"
            response = self.session.get(secret_url, headers=self._get_headers(), timeout=10)
            response.raise_for_status()
            return response.json().get("value")

        except requests.exceptions.RequestException as e:
            print(f"Warning: Could not retrieve client secret: {e}")
            return None

    def create_test_user(
        self, realm_name: str, username: str, password: str, email: Optional[str] = None
    ) -> None:
        """Create a test user in the realm."""
        url = f"{self.base_url}/admin/realms/{realm_name}/users"

        user_data = {
            "username": username,
            "enabled": True,
            "emailVerified": True,
            "email": email or f"{username}@example.com",
            "credentials": [{"type": "password", "value": password, "temporary": False}],
        }

        print(f"Creating test user '{username}' in realm '{realm_name}'...")
        try:
            response = self.session.post(
                url, json=user_data, headers=self._get_headers(), timeout=10
            )
            response.raise_for_status()
            print(f"Test user '{username}' created successfully!")
        except requests.exceptions.HTTPError as e:
            if response.status_code == 409:
                print(f"User '{username}' already exists, skipping creation.")
            else:
                print(f"Failed to create user: {e}")
                print(f"Response: {response.text}")

    def print_summary(self, realm_name: str, client_info: Dict[str, Any]) -> None:
        """Print a summary of the setup."""
        print("\n" + "=" * 70)
        print("Keycloak Setup Complete!")
        print("=" * 70)
        print(f"\nRealm: {realm_name}")
        print(f"  URL: {self.base_url}/realms/{realm_name}")
        print(f"  Admin Console: {self.base_url}/admin/{realm_name}/console/")
        print(f"\nClient: {client_info['client_id']}")
        print(f"  Type: {'Public' if client_info.get('public', True) else 'Confidential'}")
        print(f"  Device Flow: Enabled")

        if "client_secret" in client_info:
            print(f"  Client Secret: {client_info['client_secret']}")

        print(f"\nOIDC Endpoints:")
        print(f"  Token: {self.base_url}/realms/{realm_name}/protocol/openid-connect/token")
        print(
            f"  Device Auth: {self.base_url}/realms/{realm_name}/protocol/openid-connect/auth/device"
        )
        print(
            f"  Well-known: {self.base_url}/realms/{realm_name}/.well-known/openid-configuration"
        )
        print("=" * 70 + "\n")


def main() -> None:
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Setup Keycloak realm and client with device code auth flow"
    )
    parser.add_argument(
        "--realm", default="test-realm", help="Realm name (default: test-realm)"
    )
    parser.add_argument(
        "--client", default="test-client", help="Client ID (default: test-client)"
    )
    parser.add_argument(
        "--client-name", help="Client display name (default: same as client ID)"
    )
    parser.add_argument(
        "--confidential",
        action="store_true",
        help="Create confidential client instead of public",
    )
    parser.add_argument(
        "--base-url",
        default="http://keycloak:8080",
        help="Keycloak base URL (default: http://keycloak:8080)",
    )
    parser.add_argument(
        "--admin-user", default="admin", help="Admin username (default: admin)"
    )
    parser.add_argument(
        "--admin-password", default="admin", help="Admin password (default: admin)"
    )
    parser.add_argument(
        "--create-test-user",
        action="store_true",
        help="Create a test user (username: testuser, password: testpass)",
    )

    args = parser.parse_args()

    # Initialize Keycloak setup
    keycloak = KeycloakSetup(args.base_url, args.admin_user, args.admin_password)

    # Authenticate
    keycloak.authenticate()

    # Create realm
    keycloak.create_realm(args.realm)

    # Small delay to ensure realm is fully created
    time.sleep(1)

    # Create client
    client_info = keycloak.create_client(
        realm_name=args.realm,
        client_id=args.client,
        client_name=args.client_name,
        public=not args.confidential,
    )

    # Create test user if requested
    if args.create_test_user:
        keycloak.create_test_user(args.realm, "testuser", "testpass")

    # Print summary
    keycloak.print_summary(args.realm, client_info)


if __name__ == "__main__":
    main()
