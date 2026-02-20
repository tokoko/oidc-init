"""Direct file-based reader for ~/.oidc/cache/tokens/ JSON files."""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

TOKEN_DIR = Path.home() / ".oidc" / "cache" / "tokens"


class TokenNotFoundError(Exception):
    """Raised when a token file does not exist."""

    pass


class StorageError(Exception):
    """Raised on I/O or parse errors reading token files."""

    pass


def _sanitize_key(key: str) -> str:
    """Match the Go sanitizeKey: replace non-word/dash/dot chars with underscore."""
    return re.sub(r"[^\w\-.]", "_", key)


def _json_path(key: str, tokens_dir: Optional[Path] = None) -> Path:
    d = tokens_dir or TOKEN_DIR
    return d / f"{_sanitize_key(key)}.json"


def _token_path(key: str, tokens_dir: Optional[Path] = None) -> Path:
    d = tokens_dir or TOKEN_DIR
    return d / f"{_sanitize_key(key)}.token"


def read_token_data(storage_key: str, tokens_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Read and parse the JSON token file for a storage key.

    Returns the full dict: access_token, token_type, expires_at, issued_at,
    scope, refresh_token, id_token.
    """
    jp = _json_path(storage_key, tokens_dir)
    if not jp.exists():
        raise TokenNotFoundError(f"No tokens found for '{storage_key}'")
    try:
        with open(jp, "r") as f:
            data = json.load(f)
        if not isinstance(data, dict) or "access_token" not in data:
            raise StorageError(f"Invalid token file for '{storage_key}'")
        return data
    except json.JSONDecodeError as e:
        raise StorageError(f"Failed to parse token file for '{storage_key}': {e}") from e
    except IOError as e:
        raise StorageError(f"Failed to read token file for '{storage_key}': {e}") from e


def is_expired(storage_key: str, tokens_dir: Optional[Path] = None) -> bool:
    """Check if the token for storage_key has expired based on expires_at."""
    data = read_token_data(storage_key, tokens_dir)
    expires_at_str = data.get("expires_at", "")
    if not expires_at_str:
        return True
    try:
        expires_at = datetime.fromisoformat(expires_at_str)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) >= expires_at
    except ValueError:
        return True


def token_file_path(storage_key: str, tokens_dir: Optional[Path] = None) -> str:
    """Return the path to the .token file (raw access token only)."""
    tp = _token_path(storage_key, tokens_dir)
    return str(tp)


def list_keys(tokens_dir: Optional[Path] = None) -> List[str]:
    """List all storage keys found in the tokens directory."""
    d = tokens_dir or TOKEN_DIR
    if not d.exists():
        return []
    seen: set = set()
    keys: List[str] = []
    for entry in sorted(d.iterdir()):
        if entry.is_dir():
            continue
        if entry.suffix in (".json", ".token"):
            key = entry.stem
            if key not in seen:
                seen.add(key)
                keys.append(key)
    return keys


def delete_token_files(storage_key: str, tokens_dir: Optional[Path] = None) -> None:
    """Delete both .json and .token files for a storage key."""
    jp = _json_path(storage_key, tokens_dir)
    tp = _token_path(storage_key, tokens_dir)
    found = False
    for p in (jp, tp):
        if p.exists():
            p.unlink()
            found = True
    if not found:
        raise TokenNotFoundError(f"No tokens found for '{storage_key}'")


def purge_all(tokens_dir: Optional[Path] = None) -> int:
    """Delete all token files. Returns count of JSON files deleted."""
    d = tokens_dir or TOKEN_DIR
    if not d.exists():
        return 0
    count = 0
    for entry in d.iterdir():
        if entry.is_dir():
            continue
        if entry.suffix == ".json":
            count += 1
        entry.unlink()
    return count
