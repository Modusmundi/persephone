"""Configuration management CLI commands."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn

import click

if TYPE_CHECKING:
    pass

# Common option for JSON output
json_option = click.option(
    "--json",
    "output_json",
    is_flag=True,
    help="Output results as JSON for scripting",
)


def output_result(data: dict[str, Any], as_json: bool = False) -> None:
    """Output result as JSON or formatted text.

    Args:
        data: Data to output
        as_json: If True, output as JSON
    """
    if as_json:
        click.echo(json.dumps(data, indent=2, default=str))


def error_result(message: str, as_json: bool = False) -> NoReturn:
    """Output error message and exit.

    This function never returns - it either raises ClickException or calls sys.exit.

    Args:
        message: Error message
        as_json: If True, output as JSON
    """
    if as_json:
        click.echo(json.dumps({"error": message}, indent=2), err=True)
        sys.exit(1)
    raise click.ClickException(message)


@click.group()
def config() -> None:
    """Manage AuthTest configuration."""
    pass


@config.command("init")
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite existing database and key files.",
)
@json_option
def config_init(force: bool, output_json: bool) -> None:
    """Initialize configuration database.

    Creates the encryption key and encrypted SQLCipher database.
    This is the first command to run after installing AuthTest.

    Examples:

        # Initialize with default paths
        authtest config init

        # Force reinitialize (deletes existing data)
        authtest config init --force

        # JSON output for scripting
        authtest config init --json
    """
    from authtest.storage import (
        DEFAULT_DB_PATH,
        DEFAULT_KEY_PATH,
        Database,
        KeyNotFoundError,
        generate_encryption_key,
        save_encryption_key,
    )

    db_path = DEFAULT_DB_PATH
    key_path = DEFAULT_KEY_PATH

    # Check if already initialized
    if key_path.exists() and db_path.exists() and not force:
        if output_json:
            output_result({
                "status": "already_initialized",
                "database": str(db_path),
                "key_file": str(key_path),
                "message": "AuthTest is already initialized. Use --force to reinitialize.",
            }, as_json=True)
            return
        click.echo("AuthTest is already initialized.")
        click.echo(f"  Database: {db_path}")
        click.echo(f"  Key file: {key_path}")
        click.echo("")
        click.echo("Use --force to reinitialize (WARNING: this will delete existing data)")
        return

    # Check if we need to generate a new key
    need_new_key = not key_path.exists() or force

    if need_new_key:
        if not output_json:
            click.echo("Generating AES-256 encryption key...")
        key = generate_encryption_key()
        save_encryption_key(key, key_path)
        if not output_json:
            click.echo(f"Encryption key saved to: {key_path}")

    # Remove existing database if force
    if force and db_path.exists():
        db_path.unlink()
        if not output_json:
            click.echo(f"Removed existing database: {db_path}")

    # Initialize database
    if not output_json:
        click.echo(f"Creating encrypted database at: {db_path}")
    try:
        database = Database(db_path=db_path)
        database.init_db()
        database.verify_connection()
        database.close()
    except KeyNotFoundError as e:
        error_result(str(e), output_json)

    if output_json:
        output_result({
            "status": "initialized",
            "database": str(db_path),
            "key_file": str(key_path),
        }, as_json=True)
    else:
        click.echo("")
        click.echo("AuthTest initialized successfully!")
        click.echo("")
        click.echo("Next steps:")
        click.echo("  1. Run 'authtest config idp add <name>' to add an Identity Provider")
        click.echo("  2. Run 'authtest serve' to start the web interface")


@config.group("idp")
def idp() -> None:
    """Manage Identity Provider configurations.

    Identity Providers (IdPs) are the authentication services you want to test,
    such as Okta, Keycloak, Azure AD, or any SAML/OIDC provider.
    """
    pass


@idp.command("add")
@click.argument("name")
@click.option(
    "--type",
    "idp_type",
    type=click.Choice(["saml", "oidc"]),
    help="Identity Provider type",
)
@click.option("--display-name", help="Display name for the IdP")
@click.option("--entity-id", help="SAML Entity ID")
@click.option("--sso-url", help="SAML SSO URL")
@click.option("--slo-url", help="SAML SLO URL")
@click.option("--metadata-url", help="SAML metadata URL (auto-fetches configuration)")
@click.option("--issuer", help="OIDC Issuer URL")
@click.option("--authorization-endpoint", help="OIDC Authorization endpoint")
@click.option("--token-endpoint", help="OIDC Token endpoint")
@click.option("--userinfo-endpoint", help="OIDC UserInfo endpoint")
@click.option("--jwks-uri", help="OIDC JWKS URI")
@click.option(
    "--interactive/--no-interactive",
    "-i",
    default=None,
    help="Enable/disable interactive prompts",
)
@json_option
def idp_add(
    name: str,
    idp_type: str | None,
    display_name: str | None,
    entity_id: str | None,
    sso_url: str | None,
    slo_url: str | None,
    metadata_url: str | None,
    issuer: str | None,
    authorization_endpoint: str | None,
    token_endpoint: str | None,
    userinfo_endpoint: str | None,
    jwks_uri: str | None,
    interactive: bool | None,
    output_json: bool,
) -> None:
    """Add a new Identity Provider configuration.

    NAME is a unique identifier for this IdP (e.g., 'okta-prod', 'keycloak-dev').

    Examples:

        # Interactive mode - prompts for all values
        authtest config idp add my-okta -i

        # Non-interactive SAML configuration
        authtest config idp add my-saml --type saml \\
            --entity-id https://idp.example.com \\
            --sso-url https://idp.example.com/sso \\
            --display-name "Production Okta"

        # OIDC configuration with OIDC Discovery
        authtest config idp add my-oidc --type oidc \\
            --issuer https://accounts.google.com

        # JSON output for scripting
        authtest config idp add my-idp --type saml --json
    """
    from authtest.storage import Database, IdPProvider, IdPType, KeyNotFoundError

    # Determine if we should use interactive mode
    is_interactive = interactive if interactive is not None else sys.stdin.isatty() and not output_json

    # If not enough info provided in non-interactive mode, require type at minimum
    if not is_interactive and not idp_type:
        error_result("--type is required in non-interactive mode. Use -i for interactive mode.", output_json)

    try:
        database = Database()
        session = database.get_session()

        # Check if name already exists
        existing = session.query(IdPProvider).filter_by(name=name).first()
        if existing:
            session.close()
            database.close()
            error_result(f"IdP configuration '{name}' already exists. Use 'idp edit' to modify.", output_json)

        # Interactive prompts
        if is_interactive:
            if not idp_type:
                idp_type = click.prompt(
                    "IdP Type",
                    type=click.Choice(["saml", "oidc"]),
                    default="saml",
                )

            if not display_name:
                display_name = click.prompt("Display Name", default=name)

            if idp_type == "saml":
                if not entity_id:
                    entity_id = click.prompt("Entity ID", default="")
                if not sso_url:
                    sso_url = click.prompt("SSO URL", default="")
                if not slo_url:
                    slo_url = click.prompt("SLO URL (optional)", default="", show_default=False)
                if not metadata_url:
                    metadata_url = click.prompt("Metadata URL (optional)", default="", show_default=False)
            else:  # oidc
                if not issuer:
                    issuer = click.prompt("Issuer URL", default="")
                if not authorization_endpoint:
                    authorization_endpoint = click.prompt("Authorization Endpoint (optional)", default="", show_default=False)
                if not token_endpoint:
                    token_endpoint = click.prompt("Token Endpoint (optional)", default="", show_default=False)
                if not userinfo_endpoint:
                    userinfo_endpoint = click.prompt("UserInfo Endpoint (optional)", default="", show_default=False)
                if not jwks_uri:
                    jwks_uri = click.prompt("JWKS URI (optional)", default="", show_default=False)

        # Create the IdP configuration
        idp_provider = IdPProvider(
            name=name,
            display_name=display_name or name,
            idp_type=idp_type or IdPType.SAML,
            enabled=True,
            # SAML fields
            entity_id=entity_id or None,
            sso_url=sso_url or None,
            slo_url=slo_url or None,
            metadata_url=metadata_url or None,
            # OIDC fields
            issuer=issuer or None,
            authorization_endpoint=authorization_endpoint or None,
            token_endpoint=token_endpoint or None,
            userinfo_endpoint=userinfo_endpoint or None,
            jwks_uri=jwks_uri or None,
        )

        session.add(idp_provider)
        session.commit()

        result = {
            "status": "created",
            "idp": {
                "id": idp_provider.id,
                "name": idp_provider.name,
                "display_name": idp_provider.display_name,
                "type": idp_provider.idp_type,
                "enabled": idp_provider.enabled,
            },
        }

        session.close()
        database.close()

        if output_json:
            output_result(result, as_json=True)
        else:
            click.echo(f"IdP configuration '{name}' created successfully.")
            click.echo("")
            click.echo("Next steps:")
            click.echo(f"  1. Configure client credentials: authtest config idp edit {name}")
            click.echo(f"  2. Test authentication: authtest test {idp_type} --idp {name}")

    except KeyNotFoundError as e:
        error_result(f"Database not initialized: {e}\nRun 'authtest config init' first.", output_json)


@idp.command("edit")
@click.argument("name")
@click.option("--display-name", help="Display name for the IdP")
@click.option("--enabled/--disabled", default=None, help="Enable or disable the IdP")
@click.option("--entity-id", help="SAML Entity ID")
@click.option("--sso-url", help="SAML SSO URL")
@click.option("--slo-url", help="SAML SLO URL")
@click.option("--metadata-url", help="SAML metadata URL")
@click.option("--issuer", help="OIDC Issuer URL")
@click.option("--authorization-endpoint", help="OIDC Authorization endpoint")
@click.option("--token-endpoint", help="OIDC Token endpoint")
@click.option("--userinfo-endpoint", help="OIDC UserInfo endpoint")
@click.option("--jwks-uri", help="OIDC JWKS URI")
@json_option
def idp_edit(
    name: str,
    display_name: str | None,
    enabled: bool | None,
    entity_id: str | None,
    sso_url: str | None,
    slo_url: str | None,
    metadata_url: str | None,
    issuer: str | None,
    authorization_endpoint: str | None,
    token_endpoint: str | None,
    userinfo_endpoint: str | None,
    jwks_uri: str | None,
    output_json: bool,
) -> None:
    """Edit an existing Identity Provider configuration.

    NAME is the identifier of the IdP to edit.

    Examples:

        # Update display name
        authtest config idp edit my-okta --display-name "Okta Production"

        # Disable an IdP
        authtest config idp edit my-okta --disabled

        # Update SAML endpoints
        authtest config idp edit my-saml --sso-url https://new-idp.example.com/sso
    """
    from authtest.storage import Database, IdPProvider, KeyNotFoundError

    try:
        database = Database()
        session = database.get_session()

        # Find the IdP
        idp_provider = session.query(IdPProvider).filter_by(name=name).first()
        if not idp_provider:
            session.close()
            database.close()
            error_result(f"IdP configuration '{name}' not found.", output_json)

        # Track changes
        changes: dict[str, Any] = {}

        # Update fields if provided
        if display_name is not None:
            changes["display_name"] = {"old": idp_provider.display_name, "new": display_name}
            idp_provider.display_name = display_name

        if enabled is not None:
            changes["enabled"] = {"old": idp_provider.enabled, "new": enabled}
            idp_provider.enabled = enabled

        # SAML fields
        if entity_id is not None:
            changes["entity_id"] = {"old": idp_provider.entity_id, "new": entity_id}
            idp_provider.entity_id = entity_id or None

        if sso_url is not None:
            changes["sso_url"] = {"old": idp_provider.sso_url, "new": sso_url}
            idp_provider.sso_url = sso_url or None

        if slo_url is not None:
            changes["slo_url"] = {"old": idp_provider.slo_url, "new": slo_url}
            idp_provider.slo_url = slo_url or None

        if metadata_url is not None:
            changes["metadata_url"] = {"old": idp_provider.metadata_url, "new": metadata_url}
            idp_provider.metadata_url = metadata_url or None

        # OIDC fields
        if issuer is not None:
            changes["issuer"] = {"old": idp_provider.issuer, "new": issuer}
            idp_provider.issuer = issuer or None

        if authorization_endpoint is not None:
            changes["authorization_endpoint"] = {"old": idp_provider.authorization_endpoint, "new": authorization_endpoint}
            idp_provider.authorization_endpoint = authorization_endpoint or None

        if token_endpoint is not None:
            changes["token_endpoint"] = {"old": idp_provider.token_endpoint, "new": token_endpoint}
            idp_provider.token_endpoint = token_endpoint or None

        if userinfo_endpoint is not None:
            changes["userinfo_endpoint"] = {"old": idp_provider.userinfo_endpoint, "new": userinfo_endpoint}
            idp_provider.userinfo_endpoint = userinfo_endpoint or None

        if jwks_uri is not None:
            changes["jwks_uri"] = {"old": idp_provider.jwks_uri, "new": jwks_uri}
            idp_provider.jwks_uri = jwks_uri or None

        if not changes:
            session.close()
            database.close()
            if output_json:
                output_result({"status": "no_changes", "idp": name}, as_json=True)
            else:
                click.echo("No changes specified.")
            return

        session.commit()

        result = {
            "status": "updated",
            "idp": name,
            "changes": changes,
        }

        session.close()
        database.close()

        if output_json:
            output_result(result, as_json=True)
        else:
            click.echo(f"IdP configuration '{name}' updated.")
            for field, change in changes.items():
                click.echo(f"  {field}: {change['old']} -> {change['new']}")

    except KeyNotFoundError as e:
        error_result(f"Database not initialized: {e}\nRun 'authtest config init' first.", output_json)


@idp.command("remove")
@click.argument("name")
@click.option("--force", "-f", is_flag=True, help="Skip confirmation prompt")
@json_option
def idp_remove(name: str, force: bool, output_json: bool) -> None:
    """Remove an Identity Provider configuration.

    NAME is the identifier of the IdP to remove.

    This also removes associated client configurations and test results.

    Examples:

        # Remove with confirmation prompt
        authtest config idp remove my-okta

        # Remove without confirmation
        authtest config idp remove my-okta --force
    """
    from authtest.storage import Database, IdPProvider, KeyNotFoundError

    try:
        database = Database()
        session = database.get_session()

        # Find the IdP
        idp_provider = session.query(IdPProvider).filter_by(name=name).first()
        if not idp_provider:
            session.close()
            database.close()
            error_result(f"IdP configuration '{name}' not found.", output_json)

        # Confirm removal
        if not force and not output_json:
            click.confirm(
                f"Are you sure you want to remove '{name}'? This will delete associated configurations and test results.",
                abort=True,
            )

        # Store info for response
        idp_id = idp_provider.id
        client_count = len(idp_provider.client_configs)
        test_count = len(idp_provider.test_results)

        # Remove the IdP (cascade removes related records)
        session.delete(idp_provider)
        session.commit()

        result = {
            "status": "removed",
            "idp": {
                "id": idp_id,
                "name": name,
            },
            "deleted": {
                "client_configs": client_count,
                "test_results": test_count,
            },
        }

        session.close()
        database.close()

        if output_json:
            output_result(result, as_json=True)
        else:
            click.echo(f"IdP configuration '{name}' removed.")
            if client_count > 0 or test_count > 0:
                click.echo(f"  Deleted {client_count} client configuration(s)")
                click.echo(f"  Deleted {test_count} test result(s)")

    except KeyNotFoundError as e:
        error_result(f"Database not initialized: {e}\nRun 'authtest config init' first.", output_json)


@idp.command("list")
@json_option
def idp_list(output_json: bool) -> None:
    """List all configured Identity Providers.

    Examples:

        # List all IdPs
        authtest config idp list

        # List as JSON
        authtest config idp list --json
    """
    from authtest.storage import Database, IdPProvider, KeyNotFoundError

    try:
        database = Database()
        session = database.get_session()

        idps = session.query(IdPProvider).order_by(IdPProvider.name).all()

        result = {
            "count": len(idps),
            "idps": [
                {
                    "id": idp.id,
                    "name": idp.name,
                    "display_name": idp.display_name,
                    "type": idp.idp_type,
                    "enabled": idp.enabled,
                    "created_at": idp.created_at,
                    "updated_at": idp.updated_at,
                }
                for idp in idps
            ],
        }

        session.close()
        database.close()

        if output_json:
            output_result(result, as_json=True)
        else:
            if not idps:
                click.echo("No Identity Providers configured.")
                click.echo("")
                click.echo("Add one with: authtest config idp add <name>")
                return

            click.echo(f"Configured Identity Providers ({len(idps)}):")
            click.echo("")
            for idp in idps:
                status = click.style("enabled", fg="green") if idp.enabled else click.style("disabled", fg="red")
                click.echo(f"  {idp.name} ({idp.idp_type})")
                click.echo(f"    Display: {idp.display_name}")
                click.echo(f"    Status: {status}")
                click.echo("")

    except KeyNotFoundError as e:
        error_result(f"Database not initialized: {e}\nRun 'authtest config init' first.", output_json)


@idp.command("show")
@click.argument("name")
@json_option
def idp_show(name: str, output_json: bool) -> None:
    """Show detailed configuration for an Identity Provider.

    NAME is the identifier of the IdP to show.

    Examples:

        # Show IdP details
        authtest config idp show my-okta

        # Show as JSON
        authtest config idp show my-okta --json
    """
    from authtest.storage import Database, IdPProvider, KeyNotFoundError

    try:
        database = Database()
        session = database.get_session()

        idp = session.query(IdPProvider).filter_by(name=name).first()
        if not idp:
            session.close()
            database.close()
            error_result(f"IdP configuration '{name}' not found.", output_json)

        result: dict[str, Any] = {
            "id": idp.id,
            "name": idp.name,
            "display_name": idp.display_name,
            "type": idp.idp_type,
            "enabled": idp.enabled,
            "created_at": idp.created_at,
            "updated_at": idp.updated_at,
        }

        # Add type-specific fields
        if idp.idp_type == "saml":
            result["saml"] = {
                "entity_id": idp.entity_id,
                "sso_url": idp.sso_url,
                "slo_url": idp.slo_url,
                "metadata_url": idp.metadata_url,
                "has_metadata_xml": bool(idp.metadata_xml),
                "has_x509_cert": bool(idp.x509_cert),
            }
        else:  # oidc
            result["oidc"] = {
                "issuer": idp.issuer,
                "authorization_endpoint": idp.authorization_endpoint,
                "token_endpoint": idp.token_endpoint,
                "userinfo_endpoint": idp.userinfo_endpoint,
                "jwks_uri": idp.jwks_uri,
            }

        # Add client configs summary
        result["client_configs"] = len(idp.client_configs)
        result["test_results"] = len(idp.test_results)

        session.close()
        database.close()

        if output_json:
            output_result(result, as_json=True)
        else:
            status = click.style("enabled", fg="green") if idp.enabled else click.style("disabled", fg="red")
            click.echo(f"Identity Provider: {idp.name}")
            click.echo(f"  Display Name: {idp.display_name}")
            click.echo(f"  Type: {idp.idp_type}")
            click.echo(f"  Status: {status}")
            click.echo("")

            if idp.idp_type == "saml":
                click.echo("SAML Configuration:")
                click.echo(f"  Entity ID: {idp.entity_id or '(not set)'}")
                click.echo(f"  SSO URL: {idp.sso_url or '(not set)'}")
                click.echo(f"  SLO URL: {idp.slo_url or '(not set)'}")
                click.echo(f"  Metadata URL: {idp.metadata_url or '(not set)'}")
                click.echo(f"  Metadata XML: {'loaded' if idp.metadata_xml else '(not set)'}")
                click.echo(f"  X.509 Certificate: {'loaded' if idp.x509_cert else '(not set)'}")
            else:
                click.echo("OIDC Configuration:")
                click.echo(f"  Issuer: {idp.issuer or '(not set)'}")
                click.echo(f"  Authorization Endpoint: {idp.authorization_endpoint or '(not set)'}")
                click.echo(f"  Token Endpoint: {idp.token_endpoint or '(not set)'}")
                click.echo(f"  UserInfo Endpoint: {idp.userinfo_endpoint or '(not set)'}")
                click.echo(f"  JWKS URI: {idp.jwks_uri or '(not set)'}")

            click.echo("")
            click.echo(f"Client Configurations: {len(idp.client_configs)}")
            click.echo(f"Test Results: {len(idp.test_results)}")
            click.echo("")
            click.echo(f"Created: {idp.created_at}")
            click.echo(f"Updated: {idp.updated_at}")

    except KeyNotFoundError as e:
        error_result(f"Database not initialized: {e}\nRun 'authtest config init' first.", output_json)


@idp.command("from-preset")
@click.argument("name")
@click.option(
    "--preset",
    type=click.Choice(["keycloak", "okta"]),
    required=True,
    help="IdP preset to use",
)
@click.option(
    "--type",
    "idp_type",
    type=click.Choice(["saml", "oidc"]),
    default="saml",
    help="Protocol type (default: saml)",
)
@click.option("--base-url", help="IdP server base URL (Keycloak) or Okta domain")
@click.option("--realm", help="Keycloak realm name (required for keycloak preset)")
@click.option("--okta-domain", help="Okta domain (e.g., dev-123456.okta.com)")
@click.option("--app-id", help="Okta SAML app ID (optional, for app-specific URLs)")
@click.option("--authorization-server", default="default", help="Okta authorization server ID (default: 'default')")
@click.option("--display-name", help="Display name for the IdP")
@click.option("--discover/--no-discover", default=True, help="Auto-discover and fetch metadata/config")
@json_option
def idp_from_preset(
    name: str,
    preset: str,
    idp_type: str,
    base_url: str | None,
    realm: str | None,
    okta_domain: str | None,
    app_id: str | None,
    authorization_server: str,
    display_name: str | None,
    discover: bool,
    output_json: bool,
) -> None:
    """Add an Identity Provider from a preset configuration.

    This command creates an IdP configuration using pre-defined templates
    for common identity providers like Keycloak and Okta.

    Examples:

        # Add Keycloak SAML IdP
        authtest config idp from-preset my-keycloak \\
            --preset keycloak \\
            --base-url https://keycloak.example.com \\
            --realm myrealm

        # Add Keycloak OIDC IdP with auto-discovery
        authtest config idp from-preset my-keycloak-oidc \\
            --preset keycloak \\
            --type oidc \\
            --base-url https://keycloak.example.com \\
            --realm myrealm

        # Add Okta OIDC IdP
        authtest config idp from-preset my-okta \\
            --preset okta \\
            --type oidc \\
            --okta-domain dev-123456.okta.com

        # Add Okta SAML IdP with app ID
        authtest config idp from-preset my-okta-saml \\
            --preset okta \\
            --type saml \\
            --okta-domain dev-123456.okta.com \\
            --app-id exk12345

        # Add without fetching metadata
        authtest config idp from-preset my-keycloak \\
            --preset keycloak \\
            --base-url https://keycloak.example.com \\
            --realm myrealm \\
            --no-discover
    """
    from authtest.storage import Database, IdPProvider, KeyNotFoundError

    # Validate preset-specific requirements
    if preset == "keycloak":
        if not base_url:
            error_result("--base-url is required for the keycloak preset.", output_json)
        if not realm:
            error_result("--realm is required for the keycloak preset.", output_json)
    elif preset == "okta":
        if not okta_domain and not base_url:
            error_result("--okta-domain (or --base-url) is required for the okta preset.", output_json)
        # Allow base-url as fallback for okta-domain
        if not okta_domain:
            okta_domain = base_url

    try:
        database = Database()
        session = database.get_session()

        # Check if name already exists
        existing = session.query(IdPProvider).filter_by(name=name).first()
        if existing:
            session.close()
            database.close()
            error_result(f"IdP configuration '{name}' already exists.", output_json)

        # Get preset configuration
        if preset == "keycloak":
            from authtest.idp_presets.keycloak import get_oidc_preset, get_saml_preset

            preset_config = (
                get_saml_preset(base_url, realm)  # type: ignore[arg-type]
                if idp_type == "saml"
                else get_oidc_preset(base_url, realm)  # type: ignore[arg-type]
            )
        elif preset == "okta":
            from authtest.idp_presets.okta import (
                get_oidc_preset as get_okta_oidc_preset,
            )
            from authtest.idp_presets.okta import (
                get_saml_preset as get_okta_saml_preset,
            )

            if idp_type == "saml":
                preset_config = get_okta_saml_preset(okta_domain, app_id)  # type: ignore[arg-type]
            else:
                preset_config = get_okta_oidc_preset(okta_domain, authorization_server)  # type: ignore[arg-type]
        else:
            session.close()
            database.close()
            error_result(f"Unknown preset: {preset}", output_json)

        # Try to discover metadata/config if requested
        discovery_success: bool | None = None
        discovery_error: str | None = None
        if discover:
            if not output_json:
                click.echo(f"Discovering {idp_type.upper()} configuration...")

            if idp_type == "saml":
                from authtest.idp_presets.discovery import fetch_saml_metadata

                metadata_url = preset_config.get("metadata_url")
                if metadata_url:
                    saml_result = fetch_saml_metadata(metadata_url)
                    discovery_success = saml_result.success
                    discovery_error = saml_result.error
                    if saml_result.success:
                        # Update preset_config with discovered values
                        if saml_result.entity_id:
                            preset_config["entity_id"] = saml_result.entity_id
                        if saml_result.sso_url:
                            preset_config["sso_url"] = saml_result.sso_url
                        if saml_result.slo_url:
                            preset_config["slo_url"] = saml_result.slo_url
                        if saml_result.x509_cert:
                            preset_config["x509_cert"] = saml_result.x509_cert
                        if saml_result.metadata_xml:
                            preset_config["metadata_xml"] = saml_result.metadata_xml
                        if not output_json:
                            click.echo("  Metadata fetched successfully")
                    elif not output_json:
                        click.echo(f"  Warning: {saml_result.error}")
            else:  # oidc
                from authtest.idp_presets.discovery import fetch_oidc_discovery

                issuer = preset_config.get("issuer")
                if issuer:
                    oidc_result = fetch_oidc_discovery(issuer)
                    discovery_success = oidc_result.success
                    discovery_error = oidc_result.error
                    if oidc_result.success:
                        # Update preset_config with discovered values
                        if oidc_result.issuer:
                            preset_config["issuer"] = oidc_result.issuer
                        if oidc_result.authorization_endpoint:
                            preset_config["authorization_endpoint"] = oidc_result.authorization_endpoint
                        if oidc_result.token_endpoint:
                            preset_config["token_endpoint"] = oidc_result.token_endpoint
                        if oidc_result.userinfo_endpoint:
                            preset_config["userinfo_endpoint"] = oidc_result.userinfo_endpoint
                        if oidc_result.jwks_uri:
                            preset_config["jwks_uri"] = oidc_result.jwks_uri
                        if not output_json:
                            click.echo("  OIDC configuration discovered successfully")
                    elif not output_json:
                        click.echo(f"  Warning: {oidc_result.error}")

        # Create the IdP configuration
        idp_provider = IdPProvider(
            name=name,
            display_name=display_name or f"{preset.title()} - {name}",
            idp_type=idp_type,
            enabled=True,
            settings=preset_config.get("settings", {}),
            # SAML fields
            entity_id=preset_config.get("entity_id"),
            sso_url=preset_config.get("sso_url"),
            slo_url=preset_config.get("slo_url"),
            metadata_url=preset_config.get("metadata_url"),
            metadata_xml=preset_config.get("metadata_xml"),
            x509_cert=preset_config.get("x509_cert"),
            # OIDC fields
            issuer=preset_config.get("issuer"),
            authorization_endpoint=preset_config.get("authorization_endpoint"),
            token_endpoint=preset_config.get("token_endpoint"),
            userinfo_endpoint=preset_config.get("userinfo_endpoint"),
            jwks_uri=preset_config.get("jwks_uri"),
        )

        session.add(idp_provider)
        session.commit()

        result: dict[str, Any] = {
            "status": "created",
            "preset": preset,
            "idp": {
                "id": idp_provider.id,
                "name": idp_provider.name,
                "display_name": idp_provider.display_name,
                "type": idp_provider.idp_type,
                "enabled": idp_provider.enabled,
            },
            "discovery": {
                "attempted": discover,
                "success": discovery_success,
                "error": discovery_error,
            },
        }

        session.close()
        database.close()

        if output_json:
            output_result(result, as_json=True)
        else:
            click.echo("")
            click.echo(f"IdP configuration '{name}' created from {preset} preset.")
            click.echo(f"  Type: {idp_type.upper()}")
            if idp_type == "saml":
                click.echo(f"  Entity ID: {idp_provider.entity_id}")
                click.echo(f"  SSO URL: {idp_provider.sso_url}")
                click.echo(f"  Metadata URL: {idp_provider.metadata_url}")
                if idp_provider.x509_cert:
                    click.echo("  Certificate: loaded")
            else:
                click.echo(f"  Issuer: {idp_provider.issuer}")
                click.echo(f"  JWKS URI: {idp_provider.jwks_uri}")
            click.echo("")
            click.echo("Next steps:")
            click.echo(f"  1. Configure the IdP (see: authtest config idp setup-guide --preset {preset})")
            click.echo(f"  2. Test authentication: authtest test {idp_type} --idp {name}")

    except KeyNotFoundError as e:
        error_result(f"Database not initialized: {e}\nRun 'authtest config init' first.", output_json)


@idp.command("setup-guide")
@click.option(
    "--preset",
    type=click.Choice(["keycloak", "okta"]),
    required=True,
    help="IdP preset for setup guide",
)
@click.option("--base-url", help="IdP server base URL (for customized URLs)")
@click.option("--realm", help="Keycloak realm name (for customized URLs)")
@click.option("--okta-domain", help="Okta domain (for customized URLs)")
def idp_setup_guide(preset: str, base_url: str | None, realm: str | None, okta_domain: str | None) -> None:
    """Show setup guide for an IdP preset.

    Displays step-by-step instructions for configuring the IdP to work
    with AuthTest.

    Examples:

        # Show Keycloak setup guide
        authtest config idp setup-guide --preset keycloak

        # Show Keycloak guide with customized URLs
        authtest config idp setup-guide --preset keycloak \\
            --base-url https://keycloak.example.com \\
            --realm myrealm

        # Show Okta setup guide
        authtest config idp setup-guide --preset okta

        # Show Okta guide with customized domain
        authtest config idp setup-guide --preset okta \\
            --okta-domain dev-123456.okta.com
    """
    if preset == "keycloak":
        from authtest.idp_presets.keycloak import get_setup_guide

        guide = get_setup_guide(base_url, realm)
        click.echo(guide)
    elif preset == "okta":
        from authtest.idp_presets.okta import get_setup_guide as get_okta_setup_guide

        # Support both --okta-domain and --base-url for convenience
        domain = okta_domain or base_url
        guide = get_okta_setup_guide(domain)
        click.echo(guide)
    else:
        raise click.ClickException(f"Unknown preset: {preset}")


@idp.command("discover")
@click.argument("url")
@click.option(
    "--type",
    "protocol_type",
    type=click.Choice(["saml", "oidc", "auto"]),
    default="auto",
    help="Protocol type to discover (default: auto-detect)",
)
@json_option
def idp_discover(url: str, protocol_type: str, output_json: bool) -> None:
    """Discover IdP configuration from a URL.

    Fetches and parses SAML metadata or OIDC well-known configuration
    from the provided URL. Use this to verify connectivity and preview
    what configuration values will be used.

    Examples:

        # Auto-detect and discover
        authtest config idp discover https://idp.example.com

        # Discover SAML metadata
        authtest config idp discover \\
            https://keycloak.example.com/realms/test/protocol/saml/descriptor \\
            --type saml

        # Discover OIDC configuration
        authtest config idp discover \\
            https://keycloak.example.com/realms/test \\
            --type oidc
    """
    from authtest.idp_presets.discovery import fetch_oidc_discovery, fetch_saml_metadata

    # Auto-detect protocol type from URL
    if protocol_type == "auto":
        if ".well-known/openid-configuration" in url or "/protocol/openid-connect" in url:
            protocol_type = "oidc"
        elif "/saml" in url.lower() or url.endswith("/descriptor") or url.endswith("/metadata"):
            protocol_type = "saml"
        else:
            # Try OIDC first (more common for plain URLs)
            protocol_type = "oidc"

    if not output_json:
        click.echo(f"Discovering {protocol_type.upper()} configuration from {url}...")
        click.echo("")

    if protocol_type == "saml":
        saml_result = fetch_saml_metadata(url)

        if output_json:
            output_result({
                "success": saml_result.success,
                "protocol": "saml",
                "entity_id": saml_result.entity_id,
                "sso_url": saml_result.sso_url,
                "sso_binding": saml_result.sso_binding,
                "slo_url": saml_result.slo_url,
                "slo_binding": saml_result.slo_binding,
                "has_certificate": bool(saml_result.x509_cert),
                "name_id_formats": saml_result.name_id_formats,
                "error": saml_result.error,
            }, as_json=True)
        elif saml_result.success:
            click.echo("SAML IdP Metadata:")
            click.echo(f"  Entity ID: {saml_result.entity_id}")
            click.echo(f"  SSO URL: {saml_result.sso_url} ({saml_result.sso_binding})")
            if saml_result.slo_url:
                click.echo(f"  SLO URL: {saml_result.slo_url} ({saml_result.slo_binding})")
            click.echo(f"  Certificate: {'present' if saml_result.x509_cert else 'not found'}")
            if saml_result.name_id_formats:
                click.echo(f"  NameID Formats: {len(saml_result.name_id_formats)}")
                for fmt in saml_result.name_id_formats[:3]:
                    click.echo(f"    - {fmt.split(':')[-1]}")
        else:
            click.echo(f"Error: {saml_result.error}", err=True)

    else:  # oidc
        oidc_result = fetch_oidc_discovery(url)

        if output_json:
            output_result({
                "success": oidc_result.success,
                "protocol": "oidc",
                "issuer": oidc_result.issuer,
                "authorization_endpoint": oidc_result.authorization_endpoint,
                "token_endpoint": oidc_result.token_endpoint,
                "userinfo_endpoint": oidc_result.userinfo_endpoint,
                "jwks_uri": oidc_result.jwks_uri,
                "end_session_endpoint": oidc_result.end_session_endpoint,
                "scopes_supported": oidc_result.scopes_supported,
                "grant_types_supported": oidc_result.grant_types_supported,
                "error": oidc_result.error,
            }, as_json=True)
        elif oidc_result.success:
            click.echo("OIDC Configuration:")
            click.echo(f"  Issuer: {oidc_result.issuer}")
            click.echo(f"  Authorization: {oidc_result.authorization_endpoint}")
            click.echo(f"  Token: {oidc_result.token_endpoint}")
            if oidc_result.userinfo_endpoint:
                click.echo(f"  UserInfo: {oidc_result.userinfo_endpoint}")
            click.echo(f"  JWKS: {oidc_result.jwks_uri}")
            if oidc_result.end_session_endpoint:
                click.echo(f"  Logout: {oidc_result.end_session_endpoint}")
            if oidc_result.scopes_supported:
                click.echo(f"  Scopes: {', '.join(oidc_result.scopes_supported[:5])}")
        else:
            click.echo(f"Error: {oidc_result.error}", err=True)


@config.command("export")
@click.argument("output", type=click.Path(path_type=Path))  # type: ignore[type-var]
@click.option("--include-secrets", is_flag=True, help="Include client secrets in export (not recommended)")
@json_option
def config_export(output: Path, include_secrets: bool, output_json: bool) -> None:
    """Export configuration to a JSON file.

    Exports all IdP configurations, client configurations, and certificates
    to a portable JSON file. By default, sensitive data like client secrets
    is excluded.

    Examples:

        # Export configuration
        authtest config export backup.json

        # Export with secrets (use with caution)
        authtest config export backup.json --include-secrets
    """
    from authtest.storage import Certificate, ClientConfig, Database, IdPProvider, KeyNotFoundError

    try:
        database = Database()
        session = database.get_session()

        # Export IdPs
        idps = session.query(IdPProvider).all()
        idp_data = []
        for idp in idps:
            idp_export: dict[str, Any] = {
                "name": idp.name,
                "display_name": idp.display_name,
                "idp_type": idp.idp_type,
                "enabled": idp.enabled,
                "settings": idp.settings,
                # SAML
                "entity_id": idp.entity_id,
                "sso_url": idp.sso_url,
                "slo_url": idp.slo_url,
                "metadata_url": idp.metadata_url,
                "metadata_xml": idp.metadata_xml,
                "x509_cert": idp.x509_cert,
                # OIDC
                "issuer": idp.issuer,
                "authorization_endpoint": idp.authorization_endpoint,
                "token_endpoint": idp.token_endpoint,
                "userinfo_endpoint": idp.userinfo_endpoint,
                "jwks_uri": idp.jwks_uri,
            }
            idp_data.append(idp_export)

        # Export client configs
        clients = session.query(ClientConfig).all()
        client_data = []
        for client in clients:
            client_export: dict[str, Any] = {
                "name": client.name,
                "client_type": client.client_type,
                "idp_name": client.idp_provider.name,
                "client_id": client.client_id,
                "sp_entity_id": client.sp_entity_id,
                "acs_url": client.acs_url,
                "redirect_uris": client.redirect_uris,
                "scopes": client.scopes,
                "grant_types": client.grant_types,
                "settings": client.settings,
            }
            if include_secrets:
                client_export["client_secret"] = client.client_secret
                client_export["sp_private_key"] = client.sp_private_key
                client_export["sp_certificate"] = client.sp_certificate
            client_data.append(client_export)

        # Export certificates
        certs = session.query(Certificate).all()
        cert_data = []
        for cert in certs:
            cert_export: dict[str, Any] = {
                "name": cert.name,
                "purpose": cert.purpose,
                "certificate": cert.certificate,
                "certificate_chain": cert.certificate_chain,
                "subject": cert.subject,
                "issuer_cn": cert.issuer_cn,
                "serial_number": cert.serial_number,
                "not_before": cert.not_before.isoformat() if cert.not_before else None,
                "not_after": cert.not_after.isoformat() if cert.not_after else None,
                "fingerprint_sha256": cert.fingerprint_sha256,
            }
            if include_secrets:
                cert_export["private_key"] = cert.private_key
            cert_data.append(cert_export)

        session.close()
        database.close()

        export_data = {
            "version": "1.0",
            "exported_at": str(__import__("datetime").datetime.now(__import__("datetime").timezone.utc)),
            "includes_secrets": include_secrets,
            "idp_providers": idp_data,
            "client_configs": client_data,
            "certificates": cert_data,
        }

        # Write to file
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(export_data, indent=2, default=str))

        result = {
            "status": "exported",
            "file": str(output),
            "counts": {
                "idp_providers": len(idp_data),
                "client_configs": len(client_data),
                "certificates": len(cert_data),
            },
            "includes_secrets": include_secrets,
        }

        if output_json:
            output_result(result, as_json=True)
        else:
            click.echo(f"Configuration exported to: {output}")
            click.echo(f"  IdP Providers: {len(idp_data)}")
            click.echo(f"  Client Configurations: {len(client_data)}")
            click.echo(f"  Certificates: {len(cert_data)}")
            if not include_secrets:
                click.echo("")
                click.echo("Note: Secrets were excluded. Use --include-secrets to include them.")

    except KeyNotFoundError as e:
        error_result(f"Database not initialized: {e}\nRun 'authtest config init' first.", output_json)


@config.command("import")
@click.argument("input_file", type=click.Path(exists=True, path_type=Path))  # type: ignore[type-var]
@click.option("--merge/--replace", default=True, help="Merge with existing or replace all")
@click.option("--dry-run", is_flag=True, help="Show what would be imported without making changes")
@json_option
def config_import(input_file: Path, merge: bool, dry_run: bool, output_json: bool) -> None:
    """Import configuration from a JSON file.

    Imports IdP configurations, client configurations, and certificates
    from a previously exported JSON file.

    Examples:

        # Import and merge with existing config
        authtest config import backup.json

        # Replace all existing configuration
        authtest config import backup.json --replace

        # Preview what would be imported
        authtest config import backup.json --dry-run
    """
    from authtest.storage import Certificate, ClientConfig, Database, IdPProvider, KeyNotFoundError

    try:
        # Parse import file
        import_data = json.loads(input_file.read_text())

        # Validate version
        version = import_data.get("version", "unknown")
        if version != "1.0" and not output_json:
            click.echo(f"Warning: Import file version {version} may not be fully compatible.", err=True)

        database = Database()
        session = database.get_session()

        # Track what will be imported
        stats = {
            "idp_providers": {"new": 0, "updated": 0, "skipped": 0},
            "client_configs": {"new": 0, "updated": 0, "skipped": 0},
            "certificates": {"new": 0, "updated": 0, "skipped": 0},
        }

        # If replacing, clear existing data
        if not merge and not dry_run:
            session.query(ClientConfig).delete()
            session.query(Certificate).delete()
            session.query(IdPProvider).delete()
            session.commit()

        # Import IdP providers
        idp_name_to_id: dict[str, int] = {}
        for idp_data in import_data.get("idp_providers", []):
            existing = session.query(IdPProvider).filter_by(name=idp_data["name"]).first()

            if existing:
                if merge:
                    if not dry_run:
                        # Update existing
                        for key, value in idp_data.items():
                            if key != "name" and hasattr(existing, key):
                                setattr(existing, key, value)
                    stats["idp_providers"]["updated"] += 1
                    idp_name_to_id[idp_data["name"]] = existing.id
                else:
                    stats["idp_providers"]["skipped"] += 1
            else:
                if not dry_run:
                    idp = IdPProvider(**{k: v for k, v in idp_data.items() if hasattr(IdPProvider, k)})
                    session.add(idp)
                    session.flush()  # Get the ID
                    idp_name_to_id[idp_data["name"]] = idp.id
                stats["idp_providers"]["new"] += 1

        # Import client configs
        for client_data in import_data.get("client_configs", []):
            idp_name = client_data.pop("idp_name", None)
            if idp_name and not dry_run:
                # Look up IdP ID
                idp_id = idp_name_to_id.get(idp_name)
                if not idp_id:
                    idp_for_client = session.query(IdPProvider).filter_by(name=idp_name).first()
                    if idp_for_client:
                        idp_id = idp_for_client.id

                if idp_id:
                    existing_client = session.query(ClientConfig).filter_by(
                        name=client_data["name"],
                        idp_provider_id=idp_id,
                    ).first()

                    if existing_client:
                        if merge:
                            for key, value in client_data.items():
                                if hasattr(existing_client, key):
                                    setattr(existing_client, key, value)
                            stats["client_configs"]["updated"] += 1
                        else:
                            stats["client_configs"]["skipped"] += 1
                    else:
                        client = ClientConfig(
                            idp_provider_id=idp_id,
                            **{k: v for k, v in client_data.items() if hasattr(ClientConfig, k)},
                        )
                        session.add(client)
                        stats["client_configs"]["new"] += 1
            elif dry_run:
                stats["client_configs"]["new"] += 1

        # Import certificates
        for cert_data in import_data.get("certificates", []):
            # Convert ISO dates back
            for date_field in ["not_before", "not_after"]:
                if cert_data.get(date_field):
                    from datetime import datetime

                    cert_data[date_field] = datetime.fromisoformat(cert_data[date_field])

            existing_cert = session.query(Certificate).filter_by(name=cert_data["name"]).first()

            if existing_cert:
                if merge:
                    if not dry_run:
                        for key, value in cert_data.items():
                            if key != "name" and hasattr(existing_cert, key):
                                setattr(existing_cert, key, value)
                    stats["certificates"]["updated"] += 1
                else:
                    stats["certificates"]["skipped"] += 1
            else:
                if not dry_run:
                    cert = Certificate(**{k: v for k, v in cert_data.items() if hasattr(Certificate, k)})
                    session.add(cert)
                stats["certificates"]["new"] += 1

        if not dry_run:
            session.commit()

        session.close()
        database.close()

        result = {
            "status": "dry_run" if dry_run else "imported",
            "file": str(input_file),
            "mode": "merge" if merge else "replace",
            "stats": stats,
        }

        if output_json:
            output_result(result, as_json=True)
        else:
            action = "Would import" if dry_run else "Imported"
            click.echo(f"{action} from: {input_file}")
            click.echo(f"Mode: {'merge' if merge else 'replace'}")
            click.echo("")
            for category, counts in stats.items():
                click.echo(f"{category.replace('_', ' ').title()}:")
                click.echo(f"  New: {counts['new']}")
                click.echo(f"  Updated: {counts['updated']}")
                if counts["skipped"]:
                    click.echo(f"  Skipped: {counts['skipped']}")

    except json.JSONDecodeError as e:
        error_result(f"Invalid JSON file: {e}", output_json)
    except KeyNotFoundError as e:
        error_result(f"Database not initialized: {e}\nRun 'authtest config init' first.", output_json)
