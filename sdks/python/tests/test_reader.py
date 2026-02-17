"""Tests for oidc_init.reader — direct file-based token reading."""

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from oidc_init.reader import (
    TokenNotFoundError,
    StorageError,
    delete_token_files,
    is_expired,
    list_keys,
    purge_all,
    read_token_data,
    token_file_path,
)
from helpers import write_token as _write_token


class TestReadTokenData:
    def test_reads_valid_token(
        self, write_token: tuple, sample_token_json: Dict[str, Any]
    ) -> None:
        key, tokens_dir = write_token
        data = read_token_data(key, tokens_dir)
        assert data["access_token"] == sample_token_json["access_token"]
        assert data["token_type"] == "Bearer"

    def test_raises_on_missing(self, temp_tokens_dir: Path) -> None:
        with pytest.raises(TokenNotFoundError):
            read_token_data("nonexistent", temp_tokens_dir)

    def test_raises_on_invalid_json(self, temp_tokens_dir: Path) -> None:
        bad_path = temp_tokens_dir / "bad.json"
        bad_path.write_text("not json")
        with pytest.raises(StorageError, match="Failed to parse"):
            read_token_data("bad", temp_tokens_dir)

    def test_raises_on_missing_access_token(self, temp_tokens_dir: Path) -> None:
        no_token_path = temp_tokens_dir / "notoken.json"
        no_token_path.write_text(json.dumps({"token_type": "Bearer"}))
        with pytest.raises(StorageError, match="Invalid token file"):
            read_token_data("notoken", temp_tokens_dir)


class TestIsExpired:
    def test_valid_token_not_expired(self, write_token: tuple) -> None:
        key, tokens_dir = write_token
        assert not is_expired(key, tokens_dir)

    def test_expired_token(
        self, temp_tokens_dir: Path, expired_token_json: Dict[str, Any]
    ) -> None:
        _write_token(temp_tokens_dir, "expired", expired_token_json)
        assert is_expired("expired", temp_tokens_dir)

    def test_missing_expires_at_treated_as_expired(self, temp_tokens_dir: Path) -> None:
        data = {"access_token": "tok", "token_type": "Bearer"}
        json_path = temp_tokens_dir / "no-expiry.json"
        json_path.write_text(json.dumps(data))
        assert is_expired("no-expiry", temp_tokens_dir)

    def test_raises_on_missing_key(self, temp_tokens_dir: Path) -> None:
        with pytest.raises(TokenNotFoundError):
            is_expired("nonexistent", temp_tokens_dir)


class TestTokenFilePath:
    def test_returns_token_path(self, temp_tokens_dir: Path) -> None:
        path = token_file_path("my-key", temp_tokens_dir)
        assert path.endswith("my-key.token")

    def test_sanitizes_key(self, temp_tokens_dir: Path) -> None:
        path = token_file_path("host:8080/realm", temp_tokens_dir)
        assert ":" not in Path(path).name
        assert "/" not in Path(path).name


class TestListKeys:
    def test_lists_keys(self, write_token: tuple) -> None:
        key, tokens_dir = write_token
        keys = list_keys(tokens_dir)
        assert key in keys

    def test_deduplicates_json_and_token(self, write_token: tuple) -> None:
        key, tokens_dir = write_token
        keys = list_keys(tokens_dir)
        assert keys.count(key) == 1

    def test_empty_dir(self, temp_tokens_dir: Path) -> None:
        assert list_keys(temp_tokens_dir) == []

    def test_nonexistent_dir(self, tmp_path: Path) -> None:
        assert list_keys(tmp_path / "does-not-exist") == []

    def test_multiple_keys(
        self, temp_tokens_dir: Path, sample_token_json: Dict[str, Any]
    ) -> None:
        _write_token(temp_tokens_dir, "alpha", sample_token_json)
        _write_token(temp_tokens_dir, "beta", sample_token_json)
        keys = list_keys(temp_tokens_dir)
        assert sorted(keys) == ["alpha", "beta"]


class TestDeleteTokenFiles:
    def test_deletes_both_files(self, write_token: tuple) -> None:
        key, tokens_dir = write_token
        delete_token_files(key, tokens_dir)
        assert not (tokens_dir / f"{key}.json").exists()
        assert not (tokens_dir / f"{key}.token").exists()

    def test_raises_on_missing(self, temp_tokens_dir: Path) -> None:
        with pytest.raises(TokenNotFoundError):
            delete_token_files("nonexistent", temp_tokens_dir)


class TestPurgeAll:
    def test_purges_all(
        self, temp_tokens_dir: Path, sample_token_json: Dict[str, Any]
    ) -> None:
        _write_token(temp_tokens_dir, "a", sample_token_json)
        _write_token(temp_tokens_dir, "b", sample_token_json)
        count = purge_all(temp_tokens_dir)
        assert count == 2
        assert list_keys(temp_tokens_dir) == []

    def test_empty_dir(self, temp_tokens_dir: Path) -> None:
        assert purge_all(temp_tokens_dir) == 0

    def test_nonexistent_dir(self, tmp_path: Path) -> None:
        assert purge_all(tmp_path / "nope") == 0
