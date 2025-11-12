"""Profile management for storing provider configurations."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


class ProfileError(Exception):
    """Base exception for profile-related errors."""

    pass


class ProfileNotFoundError(ProfileError):
    """Raised when a profile doesn't exist."""

    pass


class ProfileExistsError(ProfileError):
    """Raised when trying to create a profile that already exists."""

    pass


# Default profile directory and file location
DEFAULT_PROFILE_DIR = Path.home() / ".oidc"
DEFAULT_PROFILE_FILE = DEFAULT_PROFILE_DIR / "profiles.json"


class ProfileManager:
    """Manage OIDC provider configuration profiles."""

    def __init__(self, profile_file: Optional[Path] = None):
        """Initialize the profile manager.

        Args:
            profile_file: Path to the profiles.json file (default: ~/.oidc/profiles.json)
        """
        self.profile_file = profile_file or DEFAULT_PROFILE_FILE

    def _ensure_profile_dir(self) -> None:
        """Ensure the profile directory exists."""
        self.profile_file.parent.mkdir(parents=True, exist_ok=True)

    def _load_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Load all profiles from the file.

        Returns:
            Dictionary of profile name -> profile data
        """
        if not self.profile_file.exists():
            return {}

        try:
            with open(self.profile_file, "r") as f:
                profiles = json.load(f)
                if not isinstance(profiles, dict):
                    raise ProfileError(f"Invalid profiles file format: expected dict, got {type(profiles)}")
                return profiles
        except json.JSONDecodeError as e:
            raise ProfileError(f"Failed to parse profiles file: {e}") from e
        except IOError as e:
            raise ProfileError(f"Failed to read profiles file: {e}") from e

    def _save_profiles(self, profiles: Dict[str, Dict[str, Any]]) -> None:
        """Save all profiles to the file.

        Args:
            profiles: Dictionary of profile name -> profile data
        """
        self._ensure_profile_dir()

        try:
            with open(self.profile_file, "w") as f:
                json.dump(profiles, f, indent=2)
        except IOError as e:
            raise ProfileError(f"Failed to write profiles file: {e}") from e

    def add_profile(
        self,
        name: str,
        endpoint: str,
        realm: str,
        client_id: str,
        client_secret: Optional[str] = None,
        scope: str = "openid profile email",
        protocol: str = "https",
        flow: str = "device",
        verify: bool = True,
        overwrite: bool = False,
        set_as_default: bool = False,
    ) -> None:
        """Add or update a profile.

        Args:
            name: Profile name (used as identifier)
            endpoint: OIDC provider endpoint
            realm: Realm or tenant name
            client_id: OAuth2/OIDC client ID
            client_secret: Optional client secret
            scope: Space-separated list of scopes
            protocol: Protocol (http or https)
            flow: Authentication flow (device, etc.)
            verify: Whether to verify SSL certificates (default: True)
            overwrite: If True, overwrite existing profile
            set_as_default: If True, set this profile as the default

        Raises:
            ProfileExistsError: If profile exists and overwrite is False
            ProfileError: For other errors
        """
        # Validate profile name
        if name.startswith("_"):
            raise ProfileError("Profile names cannot start with underscore (reserved)")

        profiles = self._load_profiles()

        if name in profiles and not overwrite:
            raise ProfileExistsError(
                f"Profile '{name}' already exists. Use --overwrite to replace it."
            )

        profiles[name] = {
            "endpoint": endpoint,
            "realm": realm,
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
            "protocol": protocol,
            "flow": flow,
            "verify": verify,
        }

        # Set as default if requested or if this is the first profile
        if set_as_default or (len([k for k in profiles.keys() if not k.startswith("_")]) == 1):
            profiles["_default"] = name

        self._save_profiles(profiles)

    def get_profile(self, name: str) -> Dict[str, Any]:
        """Get a profile by name.

        Args:
            name: Profile name

        Returns:
            Profile data dictionary

        Raises:
            ProfileNotFoundError: If profile doesn't exist
        """
        profiles = self._load_profiles()

        if name not in profiles or name.startswith("_"):
            raise ProfileNotFoundError(
                f"Profile '{name}' not found. Run 'oidc profile list' to see available profiles."
            )

        return profiles[name]

    def list_profiles(self) -> List[str]:
        """List all profile names.

        Returns:
            List of profile names (excluding internal keys like _default)
        """
        profiles = self._load_profiles()
        return sorted([k for k in profiles.keys() if not k.startswith("_")])

    def delete_profile(self, name: str) -> None:
        """Delete a profile.

        Args:
            name: Profile name

        Raises:
            ProfileNotFoundError: If profile doesn't exist
        """
        profiles = self._load_profiles()

        if name not in profiles or name.startswith("_"):
            raise ProfileNotFoundError(
                f"Profile '{name}' not found. Run 'oidc profile list' to see available profiles."
            )

        # If deleting the default profile, unset it
        if profiles.get("_default") == name:
            del profiles["_default"]

        del profiles[name]
        self._save_profiles(profiles)

    def profile_exists(self, name: str) -> bool:
        """Check if a profile exists.

        Args:
            name: Profile name

        Returns:
            True if profile exists, False otherwise
        """
        profiles = self._load_profiles()
        return name in profiles and not name.startswith("_")

    def get_default_profile(self) -> Optional[str]:
        """Get the name of the default profile.

        Returns:
            Default profile name, or None if no default is set
        """
        profiles = self._load_profiles()
        return profiles.get("_default")

    def set_default_profile(self, name: str) -> None:
        """Set a profile as the default.

        Args:
            name: Profile name to set as default

        Raises:
            ProfileNotFoundError: If profile doesn't exist
        """
        profiles = self._load_profiles()

        if name not in profiles or name.startswith("_"):
            raise ProfileNotFoundError(
                f"Profile '{name}' not found. Run 'oidc profile list' to see available profiles."
            )

        profiles["_default"] = name
        self._save_profiles(profiles)

    def unset_default_profile(self) -> None:
        """Unset the default profile."""
        profiles = self._load_profiles()

        if "_default" in profiles:
            del profiles["_default"]
            self._save_profiles(profiles)
