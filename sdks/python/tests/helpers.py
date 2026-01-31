"""Shared test helpers."""

import json
import os
from pathlib import Path
from typing import Any, Dict


def write_token(tokens_dir: Path, key: str, data: Dict[str, Any]) -> None:
    """Write token JSON and .token files to a directory."""
    json_path = tokens_dir / f"{key}.json"
    token_path = tokens_dir / f"{key}.token"

    with open(json_path, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(json_path, 0o600)

    with open(token_path, "w") as f:
        f.write(data["access_token"])
    os.chmod(token_path, 0o600)
