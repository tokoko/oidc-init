# OIDC-Init Python SDK

The `oidc-init` Python SDK provides programmatic access to cached OIDC tokens managed by the `oidc` CLI tool. The SDK reads token files directly from disk and invokes the Go CLI binary via subprocess when re-authentication is needed.

## Installation

The SDK and CLI are installed separately:

```bash
# Install the Go CLI binary (provides the `oidc` command)
# See releases at https://github.com/tokoko/oidc-init/releases
# Or build from source: go build -o oidc .

# Install the Python SDK
pip install oidc-init
```

The SDK requires the `oidc` binary to be available in `$PATH` for auto-reauthentication. You can also set the `OIDC_CLI_PATH` environment variable to point to the binary.

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

Get an access token from storage. Automatically triggers re-authentication via the CLI if the token is expired or missing.

**Parameters:**
- `storage_key` (str, optional): Profile name or storage key. If not provided, uses the default profile.

**Returns:**
- `str`: The access token

**Raises:**
- `TokenNotFoundError`: If token doesn't exist after re-auth attempt
- `ProfileNotFoundError`: If no storage key provided and no default profile set
- `AuthenticationError`: If re-authentication via CLI fails
- `CLINotFoundError`: If the `oidc` binary cannot be found

**Example:**
```python
from oidc_init import get_token

# From default profile
token = get_token()

# From specific profile
token = get_token("my-keycloak")
```

### `get_tokens(storage_key=None)`

Get all tokens (access, refresh, id) from storage. Automatically triggers re-authentication if expired.

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

### `get_token_path(storage_key=None)`

Get the file path to the raw `.token` file containing just the access token string. Useful for passing to tools that read tokens from files.

**Parameters:**
- `storage_key` (str, optional): Profile name or storage key

**Returns:**
- `str`: Absolute path to the `.token` file

**Example:**
```python
from oidc_init import get_token_path

path = get_token_path("my-keycloak")
# Use with shell commands: curl -H "Authorization: Bearer $(cat <path>)"
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

### `purge_tokens()`

Delete all stored tokens.

**Returns:**
- `int`: Number of token sets deleted

### `read_token_data(storage_key)`

Low-level function to read and parse the raw JSON token file.

**Returns:**
- `dict`: Full token data including metadata (expires_at, issued_at, scope, etc.)

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

### Use Case 3: Database Password

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

### Use Case 4: Custom CLI Binary Location

```python
import os

# Set before importing oidc_init, or in your environment
os.environ["OIDC_CLI_PATH"] = "/usr/local/bin/oidc"

from oidc_init import get_token
token = get_token("my-profile")
```

## Error Handling

```python
from oidc_init import (
    get_token,
    TokenNotFoundError,
    ProfileNotFoundError,
    StorageError,
    AuthenticationError,
    CLINotFoundError,
)

try:
    token = get_token("my-profile")

except CLINotFoundError as e:
    # oidc binary not found in PATH or OIDC_CLI_PATH
    print(f"CLI not found: {e}")
    print("Install the oidc binary or set OIDC_CLI_PATH")

except AuthenticationError as e:
    # Re-authentication via CLI failed
    print(f"Auth failed: {e}")

except TokenNotFoundError as e:
    # Token doesn't exist
    print(f"Token issue: {e}")
    print("Run 'oidc init --profile my-profile' to authenticate")

except ProfileNotFoundError as e:
    # No default profile set
    print(f"Profile issue: {e}")
    print("Either specify a profile or set a default")

except StorageError as e:
    # File I/O or parse error
    print(f"Storage error: {e}")
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
