# OIDC-Init Python SDK

The `oidc-init` package provides both a CLI tool and a Python SDK for managing OIDC tokens.

## Installation

```bash
pip install oidc-init
```

## Quick Start

### 1. Authenticate via CLI

First, obtain a token using the CLI:

```bash
# Authenticate and save as profile
oidc init --profile my-keycloak \
  --endpoint keycloak:8080 \
  --realm my-realm \
  --client-id my-client

# Set as default (optional)
oidc profile set-default my-keycloak
```

### 2. Use Token in Python Code

```python
import requests
from oidc_init import get_token

# Get token from default profile
token = get_token()

# Make authenticated API calls
response = requests.get(
    "https://api.example.com/data",
    headers={"Authorization": f"Bearer {token}"}
)
```

## SDK API Reference

### `get_token(storage_key=None)`

Get an access token from storage.

**Parameters:**
- `storage_key` (str, optional): Profile name or storage key. If not provided, uses the default profile.

**Returns:**
- `str`: The access token

**Raises:**
- `TokenNotFoundError`: If token doesn't exist or is expired
- `ProfileNotFoundError`: If no storage key provided and no default profile set

**Example:**
```python
from oidc_init import get_token

# From default profile
token = get_token()

# From specific profile
token = get_token("my-keycloak")
```

### `get_tokens(storage_key=None)`

Get all tokens (access, refresh, id) from storage.

**Parameters:**
- `storage_key` (str, optional): Profile name or storage key

**Returns:**
- `dict`: Dictionary containing:
  - `access_token`: The access token
  - `token_type`: Token type (usually "Bearer")
  - `refresh_token`: Refresh token (if available)
  - `id_token`: ID token (if available)

**Example:**
```python
from oidc_init import get_tokens

tokens = get_tokens("my-keycloak")
print(tokens['access_token'])
print(tokens['refresh_token'])
print(tokens['id_token'])
```

### `list_tokens(include_expired=False)`

List all available token storage keys.

**Parameters:**
- `include_expired` (bool): If True, include expired tokens

**Returns:**
- `list`: List of storage key strings

**Example:**
```python
from oidc_init import list_tokens

# Only valid tokens
valid = list_tokens()

# All tokens
all_tokens = list_tokens(include_expired=True)
```

### `is_token_valid(storage_key)`

Check if a token exists and is still valid.

**Parameters:**
- `storage_key` (str): Storage key or profile name

**Returns:**
- `bool`: True if valid, False otherwise

**Example:**
```python
from oidc_init import is_token_valid, get_token

if is_token_valid("my-keycloak"):
    token = get_token("my-keycloak")
else:
    print("Token expired, please re-authenticate")
```

## Common Use Cases

### Use Case 1: Simple API Client

```python
import requests
from oidc_init import get_token

def call_api(endpoint):
    """Make authenticated API call."""
    token = get_token()

    response = requests.get(
        f"https://api.example.com{endpoint}",
        headers={"Authorization": f"Bearer {token}"}
    )

    return response.json()

# Use it
data = call_api("/users")
```

### Use Case 2: Multiple Environments

```python
from oidc_init import get_token

# Dev environment
dev_token = get_token("keycloak-dev")

# Prod environment
prod_token = get_token("keycloak-prod")
```

### Use Case 3: Automatic Token Refresh

```python
from oidc_init import get_token, is_token_valid, TokenNotFoundError

def get_valid_token(profile):
    """Get token, prompting user if expired."""
    if is_token_valid(profile):
        return get_token(profile)
    else:
        print(f"Token expired. Run: oidc init --profile {profile}")
        raise TokenNotFoundError("Token expired")

# Use it
try:
    token = get_valid_token("my-keycloak")
except TokenNotFoundError:
    print("Please authenticate first")
```

### Use Case 4: Database Password

```python
from oidc_init import get_token
import psycopg2

# Use OIDC token as database password (for IAM authentication)
token = get_token("my-db-profile")

conn = psycopg2.connect(
    host="database.example.com",
    port=5432,
    user="myuser",
    password=token,
    database="mydb"
)
```

### Use Case 5: Iterate All Available Tokens

```python
from oidc_init import list_tokens, get_token

# Process all valid tokens
for profile in list_tokens():
    token = get_token(profile)
    print(f"{profile}: {token[:20]}...")
```

## Error Handling

```python
from oidc_init import (
    get_token,
    TokenNotFoundError,
    ProfileNotFoundError,
    StorageError
)

try:
    token = get_token("my-profile")

except TokenNotFoundError as e:
    # Token doesn't exist or is expired
    print(f"Token issue: {e}")
    print("Run 'oidc init --profile my-profile' to authenticate")

except ProfileNotFoundError as e:
    # No default profile set
    print(f"Profile issue: {e}")
    print("Either specify a profile or set a default")

except StorageError as e:
    # Storage/keyring issue
    print(f"Storage error: {e}")
```

## Advanced: Direct Storage Access

For advanced use cases, you can use the storage classes directly:

```python
from oidc_init import TokenStorage, ProfileManager

# Direct storage access
storage = TokenStorage()
profiles = ProfileManager()

# Get metadata without retrieving token
metadata = storage.get_metadata("my-keycloak")
print(f"Token expires at: {metadata['expires_at']}")

# Get profile configuration
config = profiles.get_profile("my-keycloak")
print(f"Endpoint: {config['endpoint']}")
print(f"Realm: {config['realm']}")
```

## Complete Example

```python
#!/usr/bin/env python3
"""Complete example: Using OIDC tokens in your application."""

import requests
from oidc_init import get_token, is_token_valid, TokenNotFoundError


class APIClient:
    """API client with OIDC authentication."""

    def __init__(self, base_url, profile="default"):
        self.base_url = base_url
        self.profile = profile

    def _get_headers(self):
        """Get authentication headers."""
        token = get_token(self.profile)
        return {"Authorization": f"Bearer {token}"}

    def get(self, endpoint):
        """Make GET request."""
        url = f"{self.base_url}{endpoint}"
        return requests.get(url, headers=self._get_headers())

    def post(self, endpoint, data):
        """Make POST request."""
        url = f"{self.base_url}{endpoint}"
        return requests.post(url, json=data, headers=self._get_headers())


# Use the client
if __name__ == "__main__":
    try:
        client = APIClient("https://api.example.com", profile="my-keycloak")

        # Make authenticated requests
        users = client.get("/users").json()
        print(f"Got {len(users)} users")

        # Create new resource
        result = client.post("/users", {"name": "Alice"}).json()
        print(f"Created user: {result}")

    except TokenNotFoundError:
        print("Please authenticate first:")
        print("  oidc init --profile my-keycloak")
```
