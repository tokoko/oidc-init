"""Tests for oidc_init public API (__init__.py)."""

import json
import os
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest

from helpers import write_token as _write_token

# Patch reader.TOKEN_DIR before importing the public API so that
# functions that don't accept tokens_dir still hit our temp directory.
import oidc_init
from oidc_init import (
    ProfileNotFoundError,
    TokenNotFoundError,
    get_token,
    get_token_path,
    get_tokens,
    is_token_valid,
    list_tokens,
    purge_tokens,
)


class TestResolveKey:
    def test_explicit_key_returned(self) -> None:
        assert oidc_init._resolve_key("my-key") == "my-key"

    def test_falls_back_to_default_profile(self, tmp_path: Path) -> None:
        oidc_dir = tmp_path / ".oidc"
        oidc_dir.mkdir()
        profiles_file = oidc_dir / "profiles.json"
        profiles_file.write_text(json.dumps({"_default": "my-default"}))
        with patch("pathlib.Path.home", return_value=tmp_path):
            result = oidc_init._resolve_key(None)
        assert result == "my-default"

    def test_raises_without_key_or_default(self, tmp_path: Path) -> None:
        with patch("pathlib.Path.home", return_value=tmp_path):
            with pytest.raises(ProfileNotFoundError):
                oidc_init._resolve_key(None)


class TestGetToken:
    def test_returns_access_token(
        self, temp_tokens_dir: Path, sample_token_json: Dict[str, Any]
    ) -> None:
        _write_token(temp_tokens_dir, "test", sample_token_json)
        with patch("oidc_init.reader.TOKEN_DIR", temp_tokens_dir):
            token = get_token("test")
        assert token == sample_token_json["access_token"]

    def test_triggers_reauth_on_expired(
        self, temp_tokens_dir: Path, expired_token_json: Dict[str, Any]
    ) -> None:
        _write_token(temp_tokens_dir, "exp", expired_token_json)
        with patch("oidc_init.reader.TOKEN_DIR", temp_tokens_dir):
            with patch("oidc_init._run_init") as mock_init:
                # After reauth the token should still be the expired one in our test
                # (in real life the binary would write a new one)
                try:
                    get_token("exp")
                except Exception:
                    pass
                mock_init.assert_called_once_with(profile="exp")

    def test_triggers_reauth_on_missing(self, temp_tokens_dir: Path) -> None:
        with patch("oidc_init.reader.TOKEN_DIR", temp_tokens_dir):
            with patch("oidc_init._run_init") as mock_init:
                with pytest.raises(TokenNotFoundError):
                    get_token("missing")
                mock_init.assert_called_once_with(profile="missing")


class TestGetTokens:
    def test_returns_all_tokens(
        self, temp_tokens_dir: Path, sample_token_json: Dict[str, Any]
    ) -> None:
        _write_token(temp_tokens_dir, "test", sample_token_json)
        with patch("oidc_init.reader.TOKEN_DIR", temp_tokens_dir):
            tokens = get_tokens("test")
        assert tokens["access_token"] == sample_token_json["access_token"]
        assert tokens["token_type"] == "Bearer"
        assert "refresh_token" in tokens
        assert "id_token" in tokens

    def test_omits_missing_optional_tokens(self, temp_tokens_dir: Path) -> None:
        data = {
            "access_token": "tok",
            "token_type": "Bearer",
            "expires_at": "2099-01-01T00:00:00+00:00",
        }
        json_path = temp_tokens_dir / "minimal.json"
        json_path.write_text(json.dumps(data))
        with patch("oidc_init.reader.TOKEN_DIR", temp_tokens_dir):
            tokens = get_tokens("minimal")
        assert "refresh_token" not in tokens
        assert "id_token" not in tokens


class TestGetTokenPath:
    def test_returns_path(
        self, temp_tokens_dir: Path, sample_token_json: Dict[str, Any]
    ) -> None:
        _write_token(temp_tokens_dir, "test", sample_token_json)
        with patch("oidc_init.reader.TOKEN_DIR", temp_tokens_dir):
            path = get_token_path("test")
        assert path.endswith("test.token")


class TestListTokens:
    def test_lists_valid_only(
        self, temp_tokens_dir: Path, sample_token_json: Dict[str, Any], expired_token_json: Dict[str, Any]
    ) -> None:
        _write_token(temp_tokens_dir, "valid", sample_token_json)
        _write_token(temp_tokens_dir, "expired", expired_token_json)
        with patch("oidc_init.reader.TOKEN_DIR", temp_tokens_dir):
            keys = list_tokens(include_expired=False)
        assert "valid" in keys
        assert "expired" not in keys

    def test_lists_all_with_include_expired(
        self, temp_tokens_dir: Path, sample_token_json: Dict[str, Any], expired_token_json: Dict[str, Any]
    ) -> None:
        _write_token(temp_tokens_dir, "valid", sample_token_json)
        _write_token(temp_tokens_dir, "expired", expired_token_json)
        with patch("oidc_init.reader.TOKEN_DIR", temp_tokens_dir):
            keys = list_tokens(include_expired=True)
        assert "valid" in keys
        assert "expired" in keys


class TestIsTokenValid:
    def test_valid(
        self, temp_tokens_dir: Path, sample_token_json: Dict[str, Any]
    ) -> None:
        _write_token(temp_tokens_dir, "test", sample_token_json)
        with patch("oidc_init.reader.TOKEN_DIR", temp_tokens_dir):
            assert is_token_valid("test") is True

    def test_expired(
        self, temp_tokens_dir: Path, expired_token_json: Dict[str, Any]
    ) -> None:
        _write_token(temp_tokens_dir, "test", expired_token_json)
        with patch("oidc_init.reader.TOKEN_DIR", temp_tokens_dir):
            assert is_token_valid("test") is False

    def test_missing(self, temp_tokens_dir: Path) -> None:
        with patch("oidc_init.reader.TOKEN_DIR", temp_tokens_dir):
            assert is_token_valid("nonexistent") is False


class TestPurgeTokens:
    def test_purges(
        self, temp_tokens_dir: Path, sample_token_json: Dict[str, Any]
    ) -> None:
        _write_token(temp_tokens_dir, "a", sample_token_json)
        _write_token(temp_tokens_dir, "b", sample_token_json)
        with patch("oidc_init.reader.TOKEN_DIR", temp_tokens_dir):
            count = purge_tokens()
        assert count == 2
