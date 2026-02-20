"""Subprocess wrapper for the Go ``oidc`` CLI binary."""

import os
import shutil
import subprocess
from typing import Optional


class AuthenticationError(Exception):
    """Raised when the oidc CLI subprocess fails."""

    pass


class CLINotFoundError(Exception):
    """Raised when the oidc binary cannot be located."""

    pass


def _find_oidc_binary() -> str:
    """Locate the oidc binary.

    Checks ``OIDC_CLI_PATH`` env var first, then ``shutil.which("oidc")``.
    """
    env_path = os.environ.get("OIDC_CLI_PATH")
    if env_path:
        if os.path.isfile(env_path) and os.access(env_path, os.X_OK):
            return env_path
        raise CLINotFoundError(f"OIDC_CLI_PATH={env_path} does not point to an executable file")

    which_path = shutil.which("oidc")
    if which_path:
        return which_path

    raise CLINotFoundError("Could not find 'oidc' binary. Install it or set OIDC_CLI_PATH.")


def run_init(profile: str, timeout: Optional[int] = None) -> None:
    """Run ``oidc init --profile <name>`` via subprocess.

    This triggers the device flow in the Go binary, which handles
    user interaction (printing verification URL, polling) and saves
    tokens to ``~/.oidc/cache/tokens/``.

    Args:
        profile: The profile name to authenticate with.
        timeout: Optional timeout in seconds for the subprocess.

    Raises:
        AuthenticationError: If the subprocess exits with non-zero status.
        CLINotFoundError: If the oidc binary cannot be found.
    """
    binary = _find_oidc_binary()
    cmd = [binary, "init", "--profile", profile]

    try:
        result = subprocess.run(
            cmd,
            timeout=timeout,
            stdin=None,
            stdout=None,
            stderr=None,
        )
        if result.returncode != 0:
            raise AuthenticationError(f"oidc init failed with exit code {result.returncode}")
    except subprocess.TimeoutExpired:
        raise AuthenticationError(f"oidc init timed out after {timeout} seconds")
    except FileNotFoundError:
        raise CLINotFoundError(f"Failed to execute: {binary}")
