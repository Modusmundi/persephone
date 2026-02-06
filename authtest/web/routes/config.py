"""Configuration management web routes.

Provides web UI for managing Identity Provider configurations,
including manual entry of SAML and OIDC endpoints, metadata import,
and configuration validation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from flask import Blueprint, flash, redirect, render_template, request, url_for
from werkzeug.wrappers import Response as WerkzeugResponse

from authtest.idp_presets.discovery import (
    fetch_oidc_discovery,
    fetch_saml_metadata,
    parse_saml_metadata,
)
from authtest.storage import Database, IdPProvider

config_bp = Blueprint(
    "config",
    __name__,
    url_prefix="/config",
)


@dataclass
class ValidationResult:
    """Result of configuration validation."""

    valid: bool
    errors: list[str]
    warnings: list[str]


def validate_saml_config(
    entity_id: str | None,
    sso_url: str | None,
    metadata_url: str | None = None,
    x509_cert: str | None = None,
) -> ValidationResult:
    """Validate SAML IdP configuration.

    Args:
        entity_id: SAML Entity ID.
        sso_url: Single Sign-On URL.
        metadata_url: Metadata URL (optional).
        x509_cert: X.509 certificate (optional).

    Returns:
        ValidationResult with errors and warnings.
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Required fields
    if not entity_id:
        errors.append("Entity ID is required")
    if not sso_url:
        errors.append("SSO URL is required")

    # URL validation
    if sso_url and not sso_url.startswith(("http://", "https://")):
        errors.append("SSO URL must be a valid HTTP(S) URL")
    if metadata_url and not metadata_url.startswith(("http://", "https://")):
        errors.append("Metadata URL must be a valid HTTP(S) URL")

    # Certificate validation
    if x509_cert:
        if "-----BEGIN CERTIFICATE-----" not in x509_cert:
            errors.append("X.509 certificate must be in PEM format")
    else:
        warnings.append("No IdP certificate configured - signature validation will be skipped")

    # Security warnings
    if sso_url and sso_url.startswith("http://"):
        warnings.append("SSO URL uses HTTP instead of HTTPS - this is insecure")

    return ValidationResult(
        valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
    )


def validate_oidc_config(
    issuer: str | None,
    authorization_endpoint: str | None = None,
    token_endpoint: str | None = None,
    jwks_uri: str | None = None,
) -> ValidationResult:
    """Validate OIDC IdP configuration.

    Args:
        issuer: OIDC Issuer URL.
        authorization_endpoint: Authorization endpoint.
        token_endpoint: Token endpoint.
        jwks_uri: JWKS URI.

    Returns:
        ValidationResult with errors and warnings.
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Required fields
    if not issuer:
        errors.append("Issuer URL is required")

    # URL validation
    for name, url in [
        ("Issuer", issuer),
        ("Authorization endpoint", authorization_endpoint),
        ("Token endpoint", token_endpoint),
        ("JWKS URI", jwks_uri),
    ]:
        if url and not url.startswith(("http://", "https://")):
            errors.append(f"{name} must be a valid HTTP(S) URL")
        if url and url.startswith("http://"):
            warnings.append(f"{name} uses HTTP instead of HTTPS - this is insecure")

    # Recommended fields
    if not authorization_endpoint:
        warnings.append("Authorization endpoint not set - use OIDC Discovery to auto-populate")
    if not token_endpoint:
        warnings.append("Token endpoint not set - use OIDC Discovery to auto-populate")
    if not jwks_uri:
        warnings.append("JWKS URI not set - token signature validation will be skipped")

    return ValidationResult(
        valid=len(errors) == 0,
        errors=errors,
        warnings=warnings,
    )


@config_bp.route("/")
def index() -> str:
    """List all configured Identity Providers."""
    database = Database()
    session = database.get_session()

    idps = session.query(IdPProvider).order_by(IdPProvider.name).all()

    # Prepare IdP data with validation status
    idp_list = []
    for idp in idps:
        idp_data: dict[str, Any] = {
            "id": idp.id,
            "name": idp.name,
            "display_name": idp.display_name,
            "type": idp.idp_type,
            "enabled": idp.enabled,
            "created_at": idp.created_at,
            "updated_at": idp.updated_at,
        }

        # Add type-specific info
        if idp.idp_type == "saml":
            idp_data["entity_id"] = idp.entity_id
            idp_data["sso_url"] = idp.sso_url
            idp_data["has_cert"] = bool(idp.x509_cert)
            validation = validate_saml_config(
                idp.entity_id, idp.sso_url, idp.metadata_url, idp.x509_cert
            )
        else:
            idp_data["issuer"] = idp.issuer
            idp_data["has_endpoints"] = bool(
                idp.authorization_endpoint and idp.token_endpoint
            )
            validation = validate_oidc_config(
                idp.issuer,
                idp.authorization_endpoint,
                idp.token_endpoint,
                idp.jwks_uri,
            )

        idp_data["valid"] = validation.valid
        idp_data["warning_count"] = len(validation.warnings)
        idp_list.append(idp_data)

    session.close()
    database.close()

    return render_template("config/index.html", idps=idp_list)


@config_bp.route("/add", methods=["GET", "POST"])
def add_idp() -> str | WerkzeugResponse:
    """Add a new Identity Provider (step 1: choose type)."""
    if request.method == "POST":
        idp_type = request.form.get("idp_type", "saml")
        if idp_type == "saml":
            return redirect(url_for("config.add_saml"))
        else:
            return redirect(url_for("config.add_oidc"))

    return render_template("config/add.html")


@config_bp.route("/add/saml", methods=["GET", "POST"])
def add_saml() -> str | WerkzeugResponse:
    """Add a new SAML Identity Provider."""
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        display_name = request.form.get("display_name", "").strip()
        entity_id = request.form.get("entity_id", "").strip()
        sso_url = request.form.get("sso_url", "").strip()
        slo_url = request.form.get("slo_url", "").strip()
        metadata_url = request.form.get("metadata_url", "").strip()
        x509_cert = request.form.get("x509_cert", "").strip()

        # Handle metadata import
        metadata_xml = request.form.get("metadata_xml", "").strip()
        if metadata_xml:
            result = parse_saml_metadata(metadata_xml)
            if result.success:
                if not entity_id:
                    entity_id = result.entity_id or ""
                if not sso_url:
                    sso_url = result.sso_url or ""
                if not slo_url:
                    slo_url = result.slo_url or ""
                if not x509_cert and result.x509_cert:
                    x509_cert = result.x509_cert
                flash("Configuration populated from metadata XML", "success")
            else:
                flash(f"Failed to parse metadata: {result.error}", "error")
                return render_template(
                    "config/add_saml.html",
                    name=name,
                    display_name=display_name,
                    entity_id=entity_id,
                    sso_url=sso_url,
                    slo_url=slo_url,
                    metadata_url=metadata_url,
                    x509_cert=x509_cert,
                    metadata_xml=metadata_xml,
                )

        # Validate configuration
        validation = validate_saml_config(entity_id, sso_url, metadata_url, x509_cert)

        # Also check name
        if not name:
            validation.errors.append("Name is required")
            validation.valid = False

        if not validation.valid:
            for error in validation.errors:
                flash(error, "error")
            return render_template(
                "config/add_saml.html",
                name=name,
                display_name=display_name,
                entity_id=entity_id,
                sso_url=sso_url,
                slo_url=slo_url,
                metadata_url=metadata_url,
                x509_cert=x509_cert,
                validation=validation,
            )

        # Check if name already exists
        database = Database()
        session = database.get_session()

        existing = session.query(IdPProvider).filter_by(name=name).first()
        if existing:
            session.close()
            database.close()
            flash(f"IdP configuration '{name}' already exists", "error")
            return render_template(
                "config/add_saml.html",
                name=name,
                display_name=display_name,
                entity_id=entity_id,
                sso_url=sso_url,
                slo_url=slo_url,
                metadata_url=metadata_url,
                x509_cert=x509_cert,
            )

        # Create the IdP
        idp = IdPProvider(
            name=name,
            display_name=display_name or name,
            idp_type="saml",
            enabled=True,
            entity_id=entity_id or None,
            sso_url=sso_url or None,
            slo_url=slo_url or None,
            metadata_url=metadata_url or None,
            metadata_xml=metadata_xml or None,
            x509_cert=x509_cert or None,
        )
        session.add(idp)
        session.commit()
        session.close()
        database.close()

        flash(f"Identity Provider '{name}' created successfully", "success")
        return redirect(url_for("config.view_idp", name=name))

    return render_template("config/add_saml.html")


@config_bp.route("/add/oidc", methods=["GET", "POST"])
def add_oidc() -> str | WerkzeugResponse:
    """Add a new OIDC Identity Provider."""
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        display_name = request.form.get("display_name", "").strip()
        issuer = request.form.get("issuer", "").strip()
        authorization_endpoint = request.form.get("authorization_endpoint", "").strip()
        token_endpoint = request.form.get("token_endpoint", "").strip()
        userinfo_endpoint = request.form.get("userinfo_endpoint", "").strip()
        jwks_uri = request.form.get("jwks_uri", "").strip()

        # Handle discovery
        if request.form.get("discover") and issuer:
            result = fetch_oidc_discovery(issuer)
            if result.success:
                if result.issuer:
                    issuer = result.issuer
                if result.authorization_endpoint and not authorization_endpoint:
                    authorization_endpoint = result.authorization_endpoint
                if result.token_endpoint and not token_endpoint:
                    token_endpoint = result.token_endpoint
                if result.userinfo_endpoint and not userinfo_endpoint:
                    userinfo_endpoint = result.userinfo_endpoint
                if result.jwks_uri and not jwks_uri:
                    jwks_uri = result.jwks_uri
                flash("Configuration discovered from OIDC well-known endpoint", "success")
            else:
                flash(f"Discovery failed: {result.error}", "error")
                return render_template(
                    "config/add_oidc.html",
                    name=name,
                    display_name=display_name,
                    issuer=issuer,
                    authorization_endpoint=authorization_endpoint,
                    token_endpoint=token_endpoint,
                    userinfo_endpoint=userinfo_endpoint,
                    jwks_uri=jwks_uri,
                )

        # If just discovering, re-render with populated fields
        if request.form.get("discover"):
            return render_template(
                "config/add_oidc.html",
                name=name,
                display_name=display_name,
                issuer=issuer,
                authorization_endpoint=authorization_endpoint,
                token_endpoint=token_endpoint,
                userinfo_endpoint=userinfo_endpoint,
                jwks_uri=jwks_uri,
            )

        # Validate configuration
        validation = validate_oidc_config(
            issuer, authorization_endpoint, token_endpoint, jwks_uri
        )

        # Also check name
        if not name:
            validation.errors.append("Name is required")
            validation.valid = False

        if not validation.valid:
            for error in validation.errors:
                flash(error, "error")
            return render_template(
                "config/add_oidc.html",
                name=name,
                display_name=display_name,
                issuer=issuer,
                authorization_endpoint=authorization_endpoint,
                token_endpoint=token_endpoint,
                userinfo_endpoint=userinfo_endpoint,
                jwks_uri=jwks_uri,
                validation=validation,
            )

        # Check if name already exists
        database = Database()
        session = database.get_session()

        existing = session.query(IdPProvider).filter_by(name=name).first()
        if existing:
            session.close()
            database.close()
            flash(f"IdP configuration '{name}' already exists", "error")
            return render_template(
                "config/add_oidc.html",
                name=name,
                display_name=display_name,
                issuer=issuer,
                authorization_endpoint=authorization_endpoint,
                token_endpoint=token_endpoint,
                userinfo_endpoint=userinfo_endpoint,
                jwks_uri=jwks_uri,
            )

        # Create the IdP
        idp = IdPProvider(
            name=name,
            display_name=display_name or name,
            idp_type="oidc",
            enabled=True,
            issuer=issuer or None,
            authorization_endpoint=authorization_endpoint or None,
            token_endpoint=token_endpoint or None,
            userinfo_endpoint=userinfo_endpoint or None,
            jwks_uri=jwks_uri or None,
        )
        session.add(idp)
        session.commit()
        session.close()
        database.close()

        flash(f"Identity Provider '{name}' created successfully", "success")
        return redirect(url_for("config.view_idp", name=name))

    return render_template("config/add_oidc.html")


@config_bp.route("/idp/<name>")
def view_idp(name: str) -> str | WerkzeugResponse:
    """View Identity Provider details."""
    database = Database()
    session = database.get_session()

    idp = session.query(IdPProvider).filter_by(name=name).first()
    if not idp:
        session.close()
        database.close()
        flash(f"Identity Provider '{name}' not found", "error")
        return redirect(url_for("config.index"))

    # Validate configuration
    if idp.idp_type == "saml":
        validation = validate_saml_config(
            idp.entity_id, idp.sso_url, idp.metadata_url, idp.x509_cert
        )
    else:
        validation = validate_oidc_config(
            idp.issuer,
            idp.authorization_endpoint,
            idp.token_endpoint,
            idp.jwks_uri,
        )

    idp_data = {
        "id": idp.id,
        "name": idp.name,
        "display_name": idp.display_name,
        "type": idp.idp_type,
        "enabled": idp.enabled,
        "created_at": idp.created_at,
        "updated_at": idp.updated_at,
        "settings": idp.settings,
        # SAML fields
        "entity_id": idp.entity_id,
        "sso_url": idp.sso_url,
        "slo_url": idp.slo_url,
        "metadata_url": idp.metadata_url,
        "metadata_xml": idp.metadata_xml,
        "x509_cert": idp.x509_cert,
        # OIDC fields
        "issuer": idp.issuer,
        "authorization_endpoint": idp.authorization_endpoint,
        "token_endpoint": idp.token_endpoint,
        "userinfo_endpoint": idp.userinfo_endpoint,
        "jwks_uri": idp.jwks_uri,
        # Counts
        "client_count": len(idp.client_configs),
        "test_count": len(idp.test_results),
    }

    session.close()
    database.close()

    return render_template(
        "config/view.html",
        idp=idp_data,
        validation=validation,
    )


@config_bp.route("/idp/<name>/edit", methods=["GET", "POST"])
def edit_idp(name: str) -> str | WerkzeugResponse:
    """Edit an Identity Provider."""
    database = Database()
    session = database.get_session()

    idp = session.query(IdPProvider).filter_by(name=name).first()
    if not idp:
        session.close()
        database.close()
        flash(f"Identity Provider '{name}' not found", "error")
        return redirect(url_for("config.index"))

    if request.method == "POST":
        # Get form data based on IdP type
        display_name = request.form.get("display_name", "").strip()
        enabled = request.form.get("enabled") == "on"

        if idp.idp_type == "saml":
            entity_id = request.form.get("entity_id", "").strip()
            sso_url = request.form.get("sso_url", "").strip()
            slo_url = request.form.get("slo_url", "").strip()
            metadata_url = request.form.get("metadata_url", "").strip()
            x509_cert = request.form.get("x509_cert", "").strip()

            # Handle metadata import
            metadata_xml = request.form.get("metadata_xml", "").strip()
            if metadata_xml and request.form.get("import_metadata"):
                saml_result = parse_saml_metadata(metadata_xml)
                if saml_result.success:
                    if saml_result.entity_id:
                        entity_id = saml_result.entity_id
                    if saml_result.sso_url:
                        sso_url = saml_result.sso_url
                    if saml_result.slo_url:
                        slo_url = saml_result.slo_url
                    if saml_result.x509_cert:
                        x509_cert = saml_result.x509_cert
                    flash("Configuration updated from metadata XML", "success")
                else:
                    flash(f"Failed to parse metadata: {saml_result.error}", "error")

            # Validate
            validation = validate_saml_config(entity_id, sso_url, metadata_url, x509_cert)
            if not validation.valid:
                for error in validation.errors:
                    flash(error, "error")
                idp_data = {
                    "name": idp.name,
                    "display_name": display_name or idp.display_name,
                    "type": idp.idp_type,
                    "enabled": enabled,
                    "entity_id": entity_id,
                    "sso_url": sso_url,
                    "slo_url": slo_url,
                    "metadata_url": metadata_url,
                    "x509_cert": x509_cert,
                    "metadata_xml": metadata_xml or idp.metadata_xml,
                }
                session.close()
                database.close()
                return render_template(
                    "config/edit_saml.html",
                    idp=idp_data,
                    validation=validation,
                )

            # Update
            idp.display_name = display_name or idp.name
            idp.enabled = enabled
            idp.entity_id = entity_id or None
            idp.sso_url = sso_url or None
            idp.slo_url = slo_url or None
            idp.metadata_url = metadata_url or None
            idp.x509_cert = x509_cert or None
            if metadata_xml:
                idp.metadata_xml = metadata_xml

        else:  # OIDC
            issuer = request.form.get("issuer", "").strip()
            authorization_endpoint = request.form.get("authorization_endpoint", "").strip()
            token_endpoint = request.form.get("token_endpoint", "").strip()
            userinfo_endpoint = request.form.get("userinfo_endpoint", "").strip()
            jwks_uri = request.form.get("jwks_uri", "").strip()

            # Handle discovery
            if request.form.get("discover") and issuer:
                oidc_result = fetch_oidc_discovery(issuer)
                if oidc_result.success:
                    if oidc_result.issuer:
                        issuer = oidc_result.issuer
                    if oidc_result.authorization_endpoint:
                        authorization_endpoint = oidc_result.authorization_endpoint
                    if oidc_result.token_endpoint:
                        token_endpoint = oidc_result.token_endpoint
                    if oidc_result.userinfo_endpoint:
                        userinfo_endpoint = oidc_result.userinfo_endpoint
                    if oidc_result.jwks_uri:
                        jwks_uri = oidc_result.jwks_uri
                    flash("Configuration discovered from OIDC well-known endpoint", "success")
                else:
                    flash(f"Discovery failed: {oidc_result.error}", "error")

            # If just discovering, re-render with populated fields
            if request.form.get("discover"):
                idp_data = {
                    "name": idp.name,
                    "display_name": display_name or idp.display_name,
                    "type": idp.idp_type,
                    "enabled": enabled,
                    "issuer": issuer,
                    "authorization_endpoint": authorization_endpoint,
                    "token_endpoint": token_endpoint,
                    "userinfo_endpoint": userinfo_endpoint,
                    "jwks_uri": jwks_uri,
                }
                session.close()
                database.close()
                return render_template("config/edit_oidc.html", idp=idp_data)

            # Validate
            validation = validate_oidc_config(
                issuer, authorization_endpoint, token_endpoint, jwks_uri
            )
            if not validation.valid:
                for error in validation.errors:
                    flash(error, "error")
                idp_data = {
                    "name": idp.name,
                    "display_name": display_name or idp.display_name,
                    "type": idp.idp_type,
                    "enabled": enabled,
                    "issuer": issuer,
                    "authorization_endpoint": authorization_endpoint,
                    "token_endpoint": token_endpoint,
                    "userinfo_endpoint": userinfo_endpoint,
                    "jwks_uri": jwks_uri,
                }
                session.close()
                database.close()
                return render_template(
                    "config/edit_oidc.html",
                    idp=idp_data,
                    validation=validation,
                )

            # Update
            idp.display_name = display_name or idp.name
            idp.enabled = enabled
            idp.issuer = issuer or None
            idp.authorization_endpoint = authorization_endpoint or None
            idp.token_endpoint = token_endpoint or None
            idp.userinfo_endpoint = userinfo_endpoint or None
            idp.jwks_uri = jwks_uri or None

        session.commit()
        session.close()
        database.close()

        flash(f"Identity Provider '{name}' updated successfully", "success")
        return redirect(url_for("config.view_idp", name=name))

    # GET - render edit form
    idp_data = {
        "name": idp.name,
        "display_name": idp.display_name,
        "type": idp.idp_type,
        "enabled": idp.enabled,
        # SAML fields
        "entity_id": idp.entity_id,
        "sso_url": idp.sso_url,
        "slo_url": idp.slo_url,
        "metadata_url": idp.metadata_url,
        "metadata_xml": idp.metadata_xml,
        "x509_cert": idp.x509_cert,
        # OIDC fields
        "issuer": idp.issuer,
        "authorization_endpoint": idp.authorization_endpoint,
        "token_endpoint": idp.token_endpoint,
        "userinfo_endpoint": idp.userinfo_endpoint,
        "jwks_uri": idp.jwks_uri,
    }

    session.close()
    database.close()

    if idp_data["type"] == "saml":
        return render_template("config/edit_saml.html", idp=idp_data)
    else:
        return render_template("config/edit_oidc.html", idp=idp_data)


@config_bp.route("/idp/<name>/delete", methods=["POST"])
def delete_idp(name: str) -> WerkzeugResponse:
    """Delete an Identity Provider."""
    database = Database()
    session = database.get_session()

    idp = session.query(IdPProvider).filter_by(name=name).first()
    if not idp:
        session.close()
        database.close()
        flash(f"Identity Provider '{name}' not found", "error")
        return redirect(url_for("config.index"))

    # Delete (cascade handles related records)
    session.delete(idp)
    session.commit()
    session.close()
    database.close()

    flash(f"Identity Provider '{name}' deleted successfully", "success")
    return redirect(url_for("config.index"))


@config_bp.route("/idp/<name>/toggle", methods=["POST"])
def toggle_idp(name: str) -> WerkzeugResponse:
    """Toggle an Identity Provider's enabled status."""
    database = Database()
    session = database.get_session()

    idp = session.query(IdPProvider).filter_by(name=name).first()
    if not idp:
        session.close()
        database.close()
        flash(f"Identity Provider '{name}' not found", "error")
        return redirect(url_for("config.index"))

    idp.enabled = not idp.enabled
    session.commit()

    status = "enabled" if idp.enabled else "disabled"
    flash(f"Identity Provider '{name}' {status}", "success")

    session.close()
    database.close()

    # Redirect back to referring page or index
    return redirect(request.referrer or url_for("config.index"))


@config_bp.route("/idp/<name>/fetch-metadata", methods=["POST"])
def fetch_metadata(name: str) -> WerkzeugResponse:
    """Fetch and update configuration from metadata URL."""
    database = Database()
    session = database.get_session()

    idp = session.query(IdPProvider).filter_by(name=name).first()
    if not idp:
        session.close()
        database.close()
        flash(f"Identity Provider '{name}' not found", "error")
        return redirect(url_for("config.index"))

    if idp.idp_type == "saml":
        if not idp.metadata_url:
            flash("No metadata URL configured", "error")
        else:
            saml_result = fetch_saml_metadata(idp.metadata_url)
            if saml_result.success:
                if saml_result.entity_id:
                    idp.entity_id = saml_result.entity_id
                if saml_result.sso_url:
                    idp.sso_url = saml_result.sso_url
                if saml_result.slo_url:
                    idp.slo_url = saml_result.slo_url
                if saml_result.x509_cert:
                    idp.x509_cert = saml_result.x509_cert
                if saml_result.metadata_xml:
                    idp.metadata_xml = saml_result.metadata_xml
                session.commit()
                flash("Configuration updated from metadata", "success")
            else:
                flash(f"Failed to fetch metadata: {saml_result.error}", "error")
    else:  # OIDC
        if not idp.issuer:
            flash("No issuer URL configured", "error")
        else:
            oidc_result = fetch_oidc_discovery(idp.issuer)
            if oidc_result.success:
                if oidc_result.authorization_endpoint:
                    idp.authorization_endpoint = oidc_result.authorization_endpoint
                if oidc_result.token_endpoint:
                    idp.token_endpoint = oidc_result.token_endpoint
                if oidc_result.userinfo_endpoint:
                    idp.userinfo_endpoint = oidc_result.userinfo_endpoint
                if oidc_result.jwks_uri:
                    idp.jwks_uri = oidc_result.jwks_uri
                session.commit()
                flash("Configuration updated from OIDC discovery", "success")
            else:
                flash(f"Failed to discover OIDC config: {oidc_result.error}", "error")

    session.close()
    database.close()

    return redirect(url_for("config.view_idp", name=name))


@config_bp.route("/validate", methods=["POST"])
def validate_config() -> dict[str, Any]:
    """Validate IdP configuration (AJAX endpoint)."""
    data = request.get_json() or {}
    idp_type = data.get("type", "saml")

    if idp_type == "saml":
        result = validate_saml_config(
            data.get("entity_id"),
            data.get("sso_url"),
            data.get("metadata_url"),
            data.get("x509_cert"),
        )
    else:
        result = validate_oidc_config(
            data.get("issuer"),
            data.get("authorization_endpoint"),
            data.get("token_endpoint"),
            data.get("jwks_uri"),
        )

    return {
        "valid": result.valid,
        "errors": result.errors,
        "warnings": result.warnings,
    }
