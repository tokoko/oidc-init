# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`oidc-init` is a CLI tool for obtaining and caching OIDC tokens from external providers, similar to how `kinit` is used in Kerberos authentication. The core logic and CLI are written in **Go**. A thin **Python SDK** wrapper is provided for programmatic access from Python applications.

## Project Structure

```
oidc-init/
├── main.go                 # Go entry point
├── go.mod / go.sum         # Go module (github.com/tokoko/oidc-init)
├── cmd/                    # CLI commands (Cobra)
│   ├── root.go
│   ├── init.go
│   ├── profile.go
│   └── token.go
├── internal/               # Go internal packages
│   ├── auth/               # Authentication orchestration
│   ├── deviceflow/         # RFC 8628 device authorization grant
│   ├── profiles/           # Profile management (~/.oidc/profiles.json)
│   └── storage/            # Token storage (~/.oidc/cache/tokens/)
├── sdks/python/            # Python SDK (thin wrapper)
│   ├── pyproject.toml      # Zero external dependencies
│   ├── oidc_init/
│   │   ├── __init__.py     # Public API: get_token, get_tokens, etc.
│   │   ├── reader.py       # Reads token JSON files from disk
│   │   └── cli.py          # Subprocess wrapper for `oidc` binary
│   └── tests/
├── compose.yaml            # Keycloak for integration tests
├── scripts/                # Setup scripts
├── Makefile                # Build/test/lint targets
└── .devcontainer/          # Dev environment (Go + Python + Keycloak)
```

- **CLI entry point**: `oidc` command (built from Go)
- **Python SDK**: `pip install oidc-init` (reads token files + subprocess to CLI for re-auth)
- **Go module**: `github.com/tokoko/oidc-init`

## Development Environment

The project uses a devcontainer with:
- Go and Python development environment
- **Keycloak** running on port 8080 for local OIDC testing
  - Admin Console: http://localhost:8080
  - Default credentials: admin/admin

## Development Commands

### Go (core CLI)
```bash
# Build the CLI binary
CGO_ENABLED=0 go build -o oidc .

# Run Go unit tests
CGO_ENABLED=0 go test ./...

# Run integration tests (requires Keycloak)
CGO_ENABLED=0 go test -v -tags integration ./...

# Format
gofmt -w .

# Lint
go vet ./...
```

### Python SDK
```bash
# Install dev dependencies
cd sdks/python && uv sync

# Run tests
cd sdks/python && uv run pytest

# Format
cd sdks/python && uv run black .

# Lint
cd sdks/python && uv run ruff check .

# Type check
cd sdks/python && uv run mypy oidc_init
```

### Makefile shortcuts
```bash
make build           # Build Go binary
make test            # Run Go + Python tests
make test-go         # Go tests only
make test-python     # Python tests only
make test-integration # Integration tests (Keycloak required)
make lint            # Lint Go + Python
make fmt             # Format Go + Python
make setup           # Start Keycloak + create test realm
make teardown        # Stop Keycloak
```

## Key Dependencies

### Go
- **cobra**: CLI framework
- No external HTTP libraries (stdlib `net/http`)

### Python SDK
- **Zero external dependencies** (stdlib only: json, subprocess, pathlib, datetime)
- Dev: pytest, black, ruff, mypy

## Architecture Notes

### Go CLI
1. Authenticates with OIDC providers (e.g., Keycloak) via Device Authorization Grant (RFC 8628)
2. Stores tokens in `~/.oidc/cache/tokens/` with restrictive file permissions
3. Manages profiles in `~/.oidc/profiles.json`
4. Provides `oidc init`, `oidc profile`, and `oidc token` command groups

### Python SDK
The Python SDK is a thin wrapper that:
1. Reads token JSON files directly from `~/.oidc/cache/tokens/` (no subprocess for reads)
2. Invokes `oidc init --profile <name>` via `subprocess.run()` when re-auth is needed
3. Locates the `oidc` binary via `OIDC_CLI_PATH` env var or `shutil.which("oidc")`
4. Exposes: `get_token()`, `get_tokens()`, `get_token_path()`, `list_tokens()`, `is_token_valid()`, `purge_tokens()`

### Protocol and SSL Verification

- **Default protocol**: HTTPS (can be overridden with `--protocol http`)
- **SSL verification**: Enabled by default
- **Disabling SSL verification**: Use `--no-verify` flag (development only)

### Token Storage

Tokens are stored in `~/.oidc/cache/tokens/`:
- JSON file: `{storage_key}.json` — full token data + metadata
- Raw token file: `{storage_key}.token` — access token string only
- Directory permissions: `0700`, File permissions: `0600`

### Profile Configuration

Profiles are stored in `~/.oidc/profiles.json` and include:
- OIDC provider endpoint, realm, and client credentials
- Authentication flow, protocol, SSL verification, scope settings

## Python Version Support

The Python SDK requires Python 3.8 or higher. Type hints should be compatible with Python 3.8 (`disallow_untyped_defs` is enabled in mypy).
