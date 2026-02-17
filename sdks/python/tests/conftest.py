"""Pytest fixtures for the Python SDK tests."""

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

import pytest

from helpers import write_token as _write_token


@pytest.fixture
def temp_tokens_dir(tmp_path: Path) -> Path:
    """Provide a temporary tokens directory."""
    tokens_dir = tmp_path / "tokens"
    tokens_dir.mkdir()
    os.chmod(tokens_dir, 0o700)
    return tokens_dir


@pytest.fixture
def sample_token_json() -> Dict[str, Any]:
    """Return a sample token data dict as the Go binary would write it."""
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(hours=1)
    return {
        "access_token": "eyJhbGciOiJSUzI1NiJ9.sample_access",
        "token_type": "Bearer",
        "expires_at": expires_at.isoformat(),
        "issued_at": now.isoformat(),
        "scope": "openid profile email",
        "refresh_token": "eyJhbGciOiJSUzI1NiJ9.sample_refresh",
        "id_token": "eyJhbGciOiJSUzI1NiJ9.sample_id",
    }


@pytest.fixture
def expired_token_json() -> Dict[str, Any]:
    """Return an expired token data dict."""
    now = datetime.now(timezone.utc)
    issued_at = now - timedelta(hours=2)
    expires_at = now - timedelta(hours=1)
    return {
        "access_token": "eyJhbGciOiJSUzI1NiJ9.expired_access",
        "token_type": "Bearer",
        "expires_at": expires_at.isoformat(),
        "issued_at": issued_at.isoformat(),
        "scope": "openid profile email",
    }


@pytest.fixture
def write_token(temp_tokens_dir: Path, sample_token_json: Dict[str, Any]) -> tuple:
    """Write a sample token file and return (key, tokens_dir)."""
    key = "test-profile"
    _write_token(temp_tokens_dir, key, sample_token_json)
    return key, temp_tokens_dir
