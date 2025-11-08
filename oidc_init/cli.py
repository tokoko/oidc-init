"""Command-line interface for oidc."""

import sys
from typing import Optional
import click
from .device_flow import initiate_device_flow, DeviceFlowError
from .profiles import ProfileManager, ProfileError, ProfileExistsError, ProfileNotFoundError
from .storage import TokenStorage, StorageError, TokenNotFoundError


@click.group(invoke_without_command=True)
@click.pass_context
@click.version_option(version="0.1.0", prog_name="oidc")
def cli(ctx: click.Context) -> None:
    """OIDC token initialization tool.

    Obtain and cache OIDC tokens from external providers.
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command()
@click.option(
    "--profile",
    default=None,
    help="Use a saved profile (alternative to specifying --endpoint, --realm, etc.)",
)
@click.option(
    "--endpoint",
    default=None,
    help="OIDC provider endpoint (e.g., keycloak:8080 or https://provider.com)",
)
@click.option(
    "--realm",
    default=None,
    help="Realm or tenant name",
)
@click.option(
    "--client-id",
    default=None,
    help="OAuth2/OIDC client ID",
)
@click.option(
    "--client-secret",
    default=None,
    help="Client secret (for confidential clients)",
)
@click.option(
    "--scope",
    default=None,
    help="Space-separated list of scopes to request (default: 'openid profile email')",
)
@click.option(
    "--flow",
    type=click.Choice(["device"], case_sensitive=False),
    default=None,
    help="Authentication flow to use (default: device)",
)
@click.option(
    "--protocol",
    type=click.Choice(["http", "https"], case_sensitive=False),
    default=None,
    help="Protocol to use if not specified in endpoint (default: http)",
)
@click.option(
    "--timeout",
    type=int,
    default=None,
    help="Custom timeout in seconds (default: server's expires_in value)",
)
@click.option(
    "--save-profile",
    default=None,
    help="Save this configuration as a profile with the given name",
)
def init(
    profile: Optional[str],
    endpoint: Optional[str],
    realm: Optional[str],
    client_id: Optional[str],
    client_secret: Optional[str],
    scope: Optional[str],
    flow: Optional[str],
    protocol: Optional[str],
    timeout: Optional[int],
    save_profile: Optional[str],
) -> None:
    """Initialize OIDC authentication and obtain tokens.

    Examples:

        # Use default profile (if set)
        oidc init

        # Device flow with Keycloak
        oidc init --endpoint keycloak:8080 --realm my-realm --client-id my-client

        # Save configuration as a profile
        oidc init --endpoint keycloak:8080 --realm my-realm --client-id my-client \\
            --save-profile my-keycloak

        # Use a saved profile
        oidc init --profile my-keycloak

        # Use profile with overrides
        oidc init --profile my-keycloak --scope "openid profile email offline_access"

        # HTTPS endpoint
        oidc init --endpoint provider.com --realm prod --client-id app --protocol https
    """
    # Load profile if specified, or use default profile
    profile_manager = ProfileManager()
    config = {}

    # Determine which profile to use
    profile_to_use = profile
    if not profile_to_use:
        # Check if there's a default profile
        default_profile = profile_manager.get_default_profile()
        if default_profile:
            profile_to_use = default_profile
            click.echo(f"Using default profile: {default_profile}")

    # Load profile configuration
    if profile_to_use:
        try:
            config = profile_manager.get_profile(profile_to_use)
            if profile:  # Only show this if user explicitly specified --profile
                click.echo(f"Using profile: {profile}")
        except ProfileNotFoundError as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)

    # Override profile settings with explicit CLI arguments
    if endpoint is not None:
        config["endpoint"] = endpoint
    if realm is not None:
        config["realm"] = realm
    if client_id is not None:
        config["client_id"] = client_id
    if client_secret is not None:
        config["client_secret"] = client_secret
    if scope is not None:
        config["scope"] = scope
    if flow is not None:
        config["flow"] = flow
    if protocol is not None:
        config["protocol"] = protocol

    # Apply defaults
    config.setdefault("scope", "openid profile email")
    config.setdefault("flow", "device")
    config.setdefault("protocol", "http")
    config.setdefault("client_secret", None)

    # Validate required parameters
    required = ["endpoint", "realm", "client_id"]
    missing = [param for param in required if param not in config or config[param] is None]
    if missing:
        click.echo(
            f"Error: Missing required parameters: {', '.join(missing)}\n"
            f"Either specify them explicitly or use --profile with a saved profile.",
            err=True,
        )
        sys.exit(1)

    # Extract final values
    final_endpoint = config["endpoint"]
    final_realm = config["realm"]
    final_client_id = config["client_id"]
    final_client_secret = config.get("client_secret")
    final_scope = config["scope"]
    final_flow = config["flow"]
    final_protocol = config["protocol"]

    # Construct the full token endpoint URL
    token_endpoint = _build_token_endpoint(final_endpoint, final_realm, final_protocol)

    click.echo(f"Initiating {final_flow} flow authentication...")
    click.echo(f"Endpoint: {token_endpoint}")
    click.echo(f"Client ID: {final_client_id}")
    click.echo(f"Scopes: {final_scope}")

    try:
        if final_flow == "device":
            tokens = initiate_device_flow(
                token_endpoint=token_endpoint,
                client_id=final_client_id,
                client_secret=final_client_secret,
                scope=final_scope,
                timeout=timeout,
            )

            # Display token information
            click.echo("\n" + "=" * 70)
            click.echo("TOKENS RECEIVED")
            click.echo("=" * 70)
            click.echo(f"Access Token: {tokens['access_token'][:50]}...")
            click.echo(f"Token Type: {tokens['token_type']}")
            click.echo(f"Expires In: {tokens['expires_in']} seconds")

            if "refresh_token" in tokens:
                click.echo(f"Refresh Token: {tokens['refresh_token'][:50]}...")

            if "id_token" in tokens:
                click.echo(f"ID Token: {tokens['id_token'][:50]}...")

            if "scope" in tokens:
                click.echo(f"Granted Scopes: {tokens['scope']}")

            click.echo("=" * 70)

            # Save profile if requested
            if save_profile:
                try:
                    profile_manager.add_profile(
                        name=save_profile,
                        endpoint=final_endpoint,
                        realm=final_realm,
                        client_id=final_client_id,
                        client_secret=final_client_secret,
                        scope=final_scope,
                        protocol=final_protocol,
                        flow=final_flow,
                        overwrite=False,
                    )
                    click.echo(f"\nProfile '{save_profile}' saved to ~/.oidc/profiles.json")
                except ProfileExistsError:
                    click.echo(
                        f"\nWarning: Profile '{save_profile}' already exists. "
                        f"Use 'oidc profile delete {save_profile}' first to replace it.",
                        err=True,
                    )

            # Store tokens
            token_storage = TokenStorage()

            # Determine storage key (use profile name if available, or auto-generate)
            storage_key = token_storage.generate_storage_key(
                endpoint=final_endpoint,
                realm=final_realm,
                client_id=final_client_id,
                profile_name=profile_to_use or save_profile,
            )

            try:
                token_storage.save_tokens(
                    storage_key=storage_key,
                    tokens=tokens,
                    scope=final_scope,
                )
                click.echo("\nTokens stored securely.")
                click.echo(f"Storage key: {storage_key}")

                # Show helpful message about auto-generated keys
                if not profile_to_use and not save_profile:
                    click.echo(
                        "\nNote: Tokens stored with auto-generated key. "
                        "Use 'oidc token list' to view all stored tokens."
                    )
            except StorageError as e:
                click.echo(f"\nWarning: Failed to store tokens: {e}", err=True)

        else:
            click.echo(f"Error: Flow '{final_flow}' is not yet implemented.", err=True)
            sys.exit(1)

    except DeviceFlowError as e:
        click.echo(f"\nAuthentication failed: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"\nUnexpected error: {e}", err=True)
        sys.exit(1)


@cli.group()
def profile() -> None:
    """Manage OIDC provider configuration profiles."""
    pass


@profile.command("add")
@click.argument("name")
@click.option(
    "--endpoint",
    required=True,
    help="OIDC provider endpoint (e.g., keycloak:8080 or https://provider.com)",
)
@click.option(
    "--realm",
    required=True,
    help="Realm or tenant name",
)
@click.option(
    "--client-id",
    required=True,
    help="OAuth2/OIDC client ID",
)
@click.option(
    "--client-secret",
    default=None,
    help="Client secret (for confidential clients)",
)
@click.option(
    "--scope",
    default="openid profile email",
    help="Space-separated list of scopes to request (default: 'openid profile email')",
)
@click.option(
    "--flow",
    type=click.Choice(["device"], case_sensitive=False),
    default="device",
    help="Authentication flow to use (default: device)",
)
@click.option(
    "--protocol",
    type=click.Choice(["http", "https"], case_sensitive=False),
    default="http",
    help="Protocol to use if not specified in endpoint (default: http)",
)
@click.option(
    "--overwrite",
    is_flag=True,
    help="Overwrite profile if it already exists",
)
@click.option(
    "--set-default",
    is_flag=True,
    help="Set this profile as the default",
)
def profile_add(
    name: str,
    endpoint: str,
    realm: str,
    client_id: str,
    client_secret: Optional[str],
    scope: str,
    flow: str,
    protocol: str,
    overwrite: bool,
    set_default: bool,
) -> None:
    """Add a new profile configuration.

    Examples:

        # Add a basic profile
        oidc profile add my-keycloak --endpoint keycloak:8080 \\
            --realm my-realm --client-id my-client

        # Add profile with custom scopes
        oidc profile add my-keycloak --endpoint keycloak:8080 \\
            --realm my-realm --client-id my-client \\
            --scope "openid profile email offline_access"

        # Add profile and set as default
        oidc profile add my-keycloak --endpoint keycloak:8080 \\
            --realm my-realm --client-id my-client --set-default
    """
    profile_manager = ProfileManager()

    try:
        profile_manager.add_profile(
            name=name,
            endpoint=endpoint,
            realm=realm,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            protocol=protocol,
            flow=flow,
            overwrite=overwrite,
            set_as_default=set_default,
        )
        click.echo(f"Profile '{name}' added successfully to ~/.oidc/profiles.json")
        if set_default or profile_manager.get_default_profile() == name:
            click.echo(f"Profile '{name}' set as default.")
    except ProfileExistsError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except ProfileError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@profile.command("list")
def profile_list() -> None:
    """List all saved profiles."""
    profile_manager = ProfileManager()

    try:
        profiles = profile_manager.list_profiles()
        default_profile = profile_manager.get_default_profile()

        if not profiles:
            click.echo("No profiles found. Use 'oidc profile add' to create one.")
            return

        click.echo("Saved profiles:")
        for profile_name in profiles:
            if profile_name == default_profile:
                click.echo(f"  - {profile_name} (default)")
            else:
                click.echo(f"  - {profile_name}")

        click.echo(f"\nTotal: {len(profiles)} profile(s)")
        if default_profile:
            click.echo(f"Default: {default_profile}")
        click.echo("\nUse 'oidc profile show <name>' to see profile details.")
    except ProfileError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@profile.command("show")
@click.argument("name")
def profile_show(name: str) -> None:
    """Show details of a specific profile."""
    profile_manager = ProfileManager()

    try:
        profile_data = profile_manager.get_profile(name)

        click.echo(f"Profile: {name}")
        click.echo("=" * 70)
        click.echo(f"Endpoint:      {profile_data['endpoint']}")
        click.echo(f"Realm:         {profile_data['realm']}")
        click.echo(f"Client ID:     {profile_data['client_id']}")
        click.echo(f"Client Secret: {'(set)' if profile_data.get('client_secret') else '(not set)'}")
        click.echo(f"Scope:         {profile_data['scope']}")
        click.echo(f"Protocol:      {profile_data['protocol']}")
        click.echo(f"Flow:          {profile_data['flow']}")
        click.echo("=" * 70)
    except ProfileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except ProfileError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@profile.command("delete")
@click.argument("name")
@click.option("--yes", is_flag=True, help="Skip confirmation prompt")
def profile_delete(name: str, yes: bool) -> None:
    """Delete a profile."""
    profile_manager = ProfileManager()

    try:
        # Check if profile exists first
        profile_manager.get_profile(name)

        # Warn if deleting default profile
        default = profile_manager.get_default_profile()
        if default == name:
            click.echo(f"Warning: '{name}' is the default profile.")

        # Confirm deletion
        if not yes:
            if not click.confirm(f"Delete profile '{name}'?"):
                click.echo("Cancelled.")
                return

        profile_manager.delete_profile(name)
        click.echo(f"Profile '{name}' deleted successfully.")

        if default == name:
            click.echo("Note: Default profile has been unset.")
    except ProfileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except ProfileError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@profile.command("set-default")
@click.argument("name")
def profile_set_default(name: str) -> None:
    """Set a profile as the default.

    The default profile will be used automatically when running 'oidc init'
    without specifying a --profile argument.

    Examples:

        # Set my-keycloak as the default profile
        oidc profile set-default my-keycloak

        # Now you can just run:
        oidc init
    """
    profile_manager = ProfileManager()

    try:
        profile_manager.set_default_profile(name)
        click.echo(f"Profile '{name}' set as default.")
    except ProfileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except ProfileError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@profile.command("unset-default")
def profile_unset_default() -> None:
    """Unset the default profile.

    After unsetting, you will need to explicitly specify --profile
    when running 'oidc init'.
    """
    profile_manager = ProfileManager()

    try:
        default = profile_manager.get_default_profile()
        if not default:
            click.echo("No default profile is set.")
            return

        profile_manager.unset_default_profile()
        click.echo(f"Default profile '{default}' has been unset.")
    except ProfileError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.group()
def token() -> None:
    """Manage stored OIDC tokens."""
    pass


@token.command("list")
def token_list() -> None:
    """List all stored tokens."""
    token_storage = TokenStorage()

    try:
        storage_keys = token_storage.list_storage_keys()

        if not storage_keys:
            click.echo("No tokens found. Run 'oidc init' to authenticate.")
            return

        click.echo("Stored tokens:")
        for storage_key in storage_keys:
            expired = token_storage.is_expired(storage_key)
            status = "EXPIRED" if expired else "valid"

            click.echo(f"  - {storage_key} ({status})")

        click.echo(f"\nTotal: {len(storage_keys)} token(s)")
        click.echo("\nUse 'oidc token show <storage-key>' to see token details.")
    except StorageError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@token.command("show")
@click.argument("storage_key")
def token_show(storage_key: str) -> None:
    """Show details of stored tokens."""
    token_storage = TokenStorage()

    try:
        metadata = token_storage.get_metadata(storage_key)
        expired = token_storage.is_expired(storage_key)

        click.echo(f"Storage key: {storage_key}")
        click.echo("=" * 70)
        click.echo(f"Token Type:       {metadata['token_type']}")
        click.echo(f"Issued At:        {metadata['issued_at']}")
        click.echo(f"Expires At:       {metadata['expires_at']}")
        click.echo(f"Status:           {'EXPIRED' if expired else 'Valid'}")
        click.echo(f"Scope:            {metadata.get('scope', 'N/A')}")
        click.echo(f"Has Refresh Token: {metadata['has_refresh_token']}")
        click.echo(f"Has ID Token:      {metadata['has_id_token']}")
        click.echo("=" * 70)

        if expired:
            click.echo(
                "\nWarning: Token has expired. Run 'oidc init' to re-authenticate."
            )
    except TokenNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except StorageError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@token.command("get")
@click.argument("storage_key", required=False)
@click.option("--access-token-only", is_flag=True, help="Only output the access token")
def token_get(storage_key: Optional[str], access_token_only: bool) -> None:
    """Get stored tokens.

    If no storage key is provided, uses the default profile.

    Examples:

        # Get token from default profile
        oidc token get

        # Get token from specific storage key
        oidc token get my-keycloak

        # Get only access token (useful for piping to other commands)
        oidc token get --access-token-only
    """
    token_storage = TokenStorage()

    # Determine storage key
    final_storage_key = storage_key
    if not final_storage_key:
        # Try to use default profile
        profile_manager = ProfileManager()
        default_profile = profile_manager.get_default_profile()
        if default_profile:
            final_storage_key = default_profile
        else:
            click.echo(
                "Error: No storage key provided and no default profile set.\n"
                "Either specify a storage key or set a default profile.",
                err=True,
            )
            sys.exit(1)

    try:
        # Check if expired
        if token_storage.is_expired(final_storage_key):
            click.echo(
                f"Warning: Token for '{final_storage_key}' has expired.\n"
                f"Run 'oidc init' to re-authenticate.",
                err=True,
            )
            sys.exit(1)

        tokens = token_storage.get_tokens(final_storage_key)

        if access_token_only:
            click.echo(tokens["access_token"])
        else:
            click.echo(f"Storage key: {final_storage_key}")
            click.echo("=" * 70)
            click.echo(f"Access Token: {tokens['access_token'][:50]}...")
            click.echo(f"Token Type: {tokens['token_type']}")

            if "refresh_token" in tokens:
                click.echo(f"Refresh Token: {tokens['refresh_token'][:50]}...")

            if "id_token" in tokens:
                click.echo(f"ID Token: {tokens['id_token'][:50]}...")

            click.echo("=" * 70)
    except TokenNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except StorageError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@token.command("delete")
@click.argument("storage_key")
@click.option("--yes", is_flag=True, help="Skip confirmation prompt")
def token_delete(storage_key: str, yes: bool) -> None:
    """Delete stored tokens."""
    token_storage = TokenStorage()

    try:
        # Check if token exists
        token_storage.get_metadata(storage_key)

        # Confirm deletion
        if not yes:
            if not click.confirm(f"Delete tokens for '{storage_key}'?"):
                click.echo("Cancelled.")
                return

        token_storage.delete_tokens(storage_key)
        click.echo(f"Tokens for '{storage_key}' deleted successfully.")
    except TokenNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except StorageError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@token.command("purge")
@click.option("--yes", is_flag=True, help="Skip confirmation prompt")
def token_purge(yes: bool) -> None:
    """Delete all stored tokens.

    This will remove ALL tokens from storage. Use with caution!

    Examples:

        # Purge with confirmation
        oidc token purge

        # Purge without confirmation
        oidc token purge --yes
    """
    token_storage = TokenStorage()

    try:
        # Get count of tokens to delete
        storage_keys = token_storage.list_storage_keys()

        if not storage_keys:
            click.echo("No tokens to purge.")
            return

        # Confirm deletion
        if not yes:
            click.echo(f"WARNING: This will delete {len(storage_keys)} token(s):")
            for key in storage_keys:
                click.echo(f"  - {key}")
            click.echo("")
            if not click.confirm("Are you sure you want to delete ALL tokens?"):
                click.echo("Cancelled.")
                return

        # Purge all tokens
        count = token_storage.purge_all_tokens()
        click.echo(f"Successfully purged {count} token(s).")

    except StorageError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


def _build_token_endpoint(endpoint: str, realm: str, protocol: str) -> str:
    """Build the OIDC token endpoint URL from components.

    Args:
        endpoint: Host and optional port (e.g., 'keycloak:8080' or 'https://provider.com')
        realm: Realm/tenant name
        protocol: Protocol to use if not in endpoint ('http' or 'https')

    Returns:
        Full token endpoint URL
    """
    # Check if endpoint already has a protocol
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        base_url = endpoint.rstrip("/")
    else:
        base_url = f"{protocol}://{endpoint}"

    # Construct Keycloak-style OIDC endpoint
    # TODO: Support other providers (detect provider type or make configurable)
    return f"{base_url}/realms/{realm}/protocol/openid-connect/token"


def main() -> None:
    """Entry point for the CLI application."""
    cli()


if __name__ == "__main__":
    main()
