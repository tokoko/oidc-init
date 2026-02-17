# oidc-init

A CLI tool for obtaining and caching OIDC tokens from external providers, similar to how `kinit` works for Kerberos. A thin Python SDK is also provided for programmatic access.

## Installation

### CLI (Go)

```bash
go install github.com/tokoko/oidc-init@latest
```

### Python SDK

```bash
pip install oidc-init
```

The Python SDK requires the `oidc` binary on your `PATH` (or set `OIDC_CLI_PATH`).

## Quick Start

Authenticate against an OIDC provider using the device authorization flow:

```bash
oidc init --endpoint keycloak.example.com --realm my-realm --client-id my-client
```

Save the configuration as a profile for reuse:

```bash
oidc init --endpoint keycloak.example.com --realm my-realm --client-id my-client \
  --save-profile prod
```

Then authenticate with just:

```bash
oidc init --profile prod
```

## CLI Usage

### `oidc init` — Authenticate and obtain tokens

```bash
# Device authorization flow (default)
oidc init --endpoint keycloak.example.com --realm my-realm --client-id my-client

# With a client secret
oidc init --endpoint keycloak.example.com --realm my-realm \
  --client-id my-client --client-secret s3cret

# Password (ROPC) flow
oidc init --endpoint keycloak.example.com --realm my-realm \
  --client-id my-client --flow ropc --username alice

# Use HTTP and disable SSL verification (development only)
oidc init --endpoint localhost:8080 --realm dev --client-id dev-client \
  --protocol http --no-verify
```

### `oidc profile` — Manage saved profiles

```bash
# Add a profile
oidc profile add prod \
  --endpoint keycloak.example.com --realm prod \
  --client-id myapp --client-secret s3cret --set-default

# List profiles
oidc profile list

# Show profile details
oidc profile show prod

# Set default profile
oidc profile set-default prod

# Delete a profile
oidc profile delete prod
```

### `oidc token` — Manage stored tokens

```bash
# List all stored tokens
oidc token list

# Get access token as plain string
oidc token get --access-token-only

# Get full token data as JSON
oidc token get prod

# Get path to the raw token file
oidc token path prod

# Delete a specific token
oidc token delete prod

# Purge all tokens
oidc token purge
```

## Python SDK Usage

```python
from oidc_init import get_token, get_tokens, get_token_path, is_token_valid, list_tokens

# Get an access token (re-authenticates automatically if expired)
token = get_token("prod")
headers = {"Authorization": f"Bearer {token}"}

# Use the default profile
token = get_token()

# Get all token fields (access_token, refresh_token, id_token, etc.)
tokens = get_tokens("prod")

# Get path to the raw token file
path = get_token_path("prod")

# Check if a token is still valid without triggering re-auth
if is_token_valid("prod"):
    print("Token is valid")

# List stored tokens
for key in list_tokens():
    print(key)
```

## Token Storage

Tokens are stored in `~/.oidc/cache/tokens/` with restrictive permissions (`0600`). Each token produces two files:

- `{key}.json` — full token data and metadata
- `{key}.token` — raw access token string

Profiles are stored in `~/.oidc/profiles.json`.
