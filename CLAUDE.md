# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`oidc-init` is a CLI tool for obtaining and caching OIDC tokens from external providers, similar to how `kinit` is used in Kerberos authentication. The tool allows users to authenticate once and maintain cached tokens for subsequent use.

## Project Structure

- **Package name**: `oidc-init` (with hyphen for distribution)
- **Module name**: `oidc_init` (with underscore for Python imports)
- **CLI entry point**: `oidc` command → `oidc_init.cli:main`

## Development Environment

The project uses a devcontainer with:
- Python development environment
- **Keycloak** running on port 8080 for local OIDC testing
  - Admin Console: http://localhost:8080
  - Default credentials: admin/admin
- All dependencies managed via `uv`

## Development Commands

### Setup
```bash
# Install dependencies using uv
uv sync

# Add a new dependency
uv add <package>

# Add a dev dependency
uv add --dev <package>
```

### Testing
```bash
# Run all tests with coverage
uv run pytest

# Run specific test file
uv run pytest tests/test_<module>.py

# Run specific test function
uv run pytest tests/test_<module>.py::test_<function>
```

### Code Quality
```bash
# Format code with Black (line length: 100)
uv run black .

# Lint with Ruff
uv run ruff check .

# Type check with mypy
uv run mypy oidc_init
```

## Key Dependencies

- **click**: CLI framework
- **requests**: HTTP library for OIDC/OAuth2 flows

## Architecture Notes

The tool is designed to:
1. Authenticate with external OIDC providers (e.g., Keycloak)
2. Obtain access/refresh tokens via OAuth2/OIDC flows (currently supports Device Authorization Grant - RFC 8628)
3. Store tokens securely in local file system (`~/.oidc/cache/tokens/`) with restrictive file permissions (0600)
4. Provide cached tokens to applications that need them
5. Handle token refresh automatically when expired

### Protocol and SSL Verification

- **Default protocol**: HTTPS (can be overridden with `--protocol http`)
- **SSL verification**: Enabled by default for security
- **Disabling SSL verification**: Use `--no-verify` flag when needed (e.g., self-signed certificates in development)
  - ⚠️ Use with caution - only for development/testing environments
  - A warning is displayed when SSL verification is disabled

### Token Storage

Tokens are stored in `~/.oidc/cache/tokens/` with the following structure:
- Each profile/storage key has its own JSON file: `~/.oidc/cache/tokens/{storage_key}.json`
- Files contain both tokens and metadata (expiry, scope, etc.)
- Directory permissions: `0700` (owner read/write/execute only)
- File permissions: `0600` (owner read/write only)
- Suitable for containerized and shared environments where OS keyrings are not available

### Profile Configuration

Profiles are stored in `~/.oidc/profiles.json` and include:
- OIDC provider endpoint, realm, and client credentials
- Authentication flow settings
- Protocol preference (HTTP/HTTPS)
- SSL verification setting (`verify: true/false`)
- Scope configuration

## Python Version Support

Requires Python 3.8 or higher. Type hints should be compatible with Python 3.8 (`disallow_untyped_defs` is enabled in mypy).
