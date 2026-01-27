"""Pytest configuration and fixtures for oidc-init tests."""

import pytest
from pathlib import Path
from typing import Dict, Any

from oidc_init.storage import TokenStorage


@pytest.fixture
def temp_token_storage(tmp_path: Path) -> TokenStorage:
    """Provide a TokenStorage instance using a temporary directory."""
    tokens_dir = tmp_path / "tokens"
    tokens_dir.mkdir()
    return TokenStorage(tokens_dir=tokens_dir)


@pytest.fixture
def sample_tokens() -> Dict[str, Any]:
    """Provide sample token data for unit tests."""
    return {
        "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.sample_access_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.sample_refresh_token",
        "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.sample_id_token",
        "scope": "openid profile email",
    }
