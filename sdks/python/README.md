# oidc-init Python SDK

Thin Python wrapper for reading cached OIDC tokens managed by the [`oidc` CLI](https://github.com/tokoko/oidc-init). Zero runtime dependencies.

## Install

```bash
pip install oidc-init
```

The `oidc` CLI binary must be in `$PATH` (or set `OIDC_CLI_PATH`) for auto-reauthentication.

## Usage

```python
from oidc_init import get_token

# From default profile
token = get_token()

# From a specific profile
token = get_token("my-keycloak")
```

## API

| Function | Description |
|---|---|
| `get_token(storage_key=None)` | Get access token (auto-reauths if expired) |
| `get_tokens(storage_key=None)` | Get all tokens (access, refresh, id) as dict |
| `get_token_path(storage_key=None)` | Get path to raw `.token` file |
| `list_tokens(include_expired=False)` | List available storage keys |
| `is_token_valid(storage_key)` | Check if token exists and is valid |
| `purge_tokens()` | Delete all stored tokens |
| `read_token_data(storage_key)` | Read raw token JSON data |

## Error Handling

```python
from oidc_init import (
    get_token,
    CLINotFoundError,        # oidc binary not found
    AuthenticationError,     # CLI re-auth failed
    TokenNotFoundError,      # token file missing
    ProfileNotFoundError,    # no key given, no default set
    StorageError,            # file I/O or parse error
)

try:
    token = get_token("my-profile")
except CLINotFoundError:
    print("Install the oidc binary or set OIDC_CLI_PATH")
except TokenNotFoundError:
    print("Run: oidc init --profile my-profile")
```

## Requirements

- Python >= 3.8
- `oidc` CLI binary (for re-authentication)
