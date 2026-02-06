"""Token manipulation tools routes."""

from __future__ import annotations

import json
from pathlib import Path

from flask import (
    Blueprint,
    flash,
    render_template,
    request,
    session,
)

from authtest.core.crypto.tokens import (
    JWTManipulator,
    decode_jwt_parts,
    generate_signing_key_pair,
    get_private_key_pem,
    get_public_key_jwk,
    get_public_key_pem,
)
from authtest.core.saml.manipulation import (
    SAMLManipulator,
    get_nameid_from_assertion,
    parse_saml_attributes,
)

# Get the directories relative to this package
_web_dir = Path(__file__).parent.parent
_templates_dir = _web_dir / "templates"

tools_bp = Blueprint(
    "tools",
    __name__,
    template_folder=str(_templates_dir),
    url_prefix="/tools",
)

# Session keys for storing generated keys
JWT_SIGNING_KEY_SESSION = "jwt_signing_key"
SAML_SIGNING_KEY_SESSION = "saml_signing_key"


@tools_bp.route("/")
def index() -> str:
    """Token manipulation tools home page."""
    return render_template("tools/index.html")


@tools_bp.route("/jwt", methods=["GET", "POST"])
def jwt_manipulator() -> str:
    """JWT token manipulation tool."""
    result = None
    error = None
    decoded_token = None
    original_token = ""

    if request.method == "POST":
        original_token = request.form.get("token", "").strip()
        action = request.form.get("action", "decode")

        if not original_token:
            error = "Please provide a JWT token"
        else:
            try:
                # Decode the token first
                header, payload, signature = decode_jwt_parts(original_token)
                decoded_token = {
                    "header": header,
                    "payload": payload,
                    "signature": signature,
                }

                if action == "decode":
                    # Just decode, no manipulation
                    pass

                elif action == "strip_signature":
                    # Strip signature (alg=none attack)
                    manipulator = JWTManipulator(original_token)
                    result = manipulator.strip_signature()

                elif action == "extend_expiration":
                    # Extend expiration
                    hours = int(request.form.get("extend_hours", 24))
                    sign_method = request.form.get("sign_method", "unsigned")

                    manipulator = JWTManipulator(original_token)
                    manipulator.extend_expiration(hours=hours)

                    if sign_method == "unsigned":
                        result = manipulator.build_unsigned()
                    elif sign_method == "strip":
                        result = manipulator.strip_signature()
                    else:
                        # Generate a new key and sign
                        private_key, public_key, key_id = generate_signing_key_pair("RS256")
                        result = manipulator.sign_with_rsa_key(
                            private_key,
                            algorithm="RS256",
                            key_description="AuthTest-generated RSA key",
                        )
                        # Store key in session for reference
                        session[JWT_SIGNING_KEY_SESSION] = {
                            "private_key_pem": get_private_key_pem(private_key),
                            "public_key_pem": get_public_key_pem(public_key),
                            "jwk": get_public_key_jwk(public_key, key_id, "RS256"),
                        }

                elif action == "modify_claims":
                    # Modify specific claims
                    manipulator = JWTManipulator(original_token)

                    # Apply modifications from form
                    if request.form.get("new_sub"):
                        manipulator.change_subject(request.form.get("new_sub", ""))
                    if request.form.get("new_iss"):
                        manipulator.change_issuer(request.form.get("new_iss", ""))
                    if request.form.get("new_aud"):
                        manipulator.change_audience(request.form.get("new_aud", ""))
                    if request.form.get("add_admin") == "on":
                        manipulator.set_admin()
                    if request.form.get("add_role"):
                        manipulator.add_role(request.form.get("add_role", ""))

                    # Custom claim modifications
                    custom_claim = request.form.get("custom_claim_name")
                    custom_value = request.form.get("custom_claim_value")
                    if custom_claim and custom_value:
                        # Try to parse as JSON first
                        try:
                            parsed_value = json.loads(custom_value)
                        except json.JSONDecodeError:
                            parsed_value = custom_value
                        manipulator.modify_claim(custom_claim, parsed_value, add_if_missing=True)

                    sign_method = request.form.get("sign_method", "unsigned")

                    if sign_method == "unsigned":
                        result = manipulator.build_unsigned()
                    elif sign_method == "strip":
                        result = manipulator.strip_signature()
                    else:
                        # Generate a new key and sign
                        private_key, public_key, key_id = generate_signing_key_pair("RS256")
                        result = manipulator.sign_with_rsa_key(
                            private_key,
                            algorithm="RS256",
                            key_description="AuthTest-generated RSA key",
                        )
                        session[JWT_SIGNING_KEY_SESSION] = {
                            "private_key_pem": get_private_key_pem(private_key),
                            "public_key_pem": get_public_key_pem(public_key),
                            "jwk": get_public_key_jwk(public_key, key_id, "RS256"),
                        }

                elif action == "algorithm_confusion":
                    # Algorithm confusion attack (RS256 -> HS256)
                    secret = request.form.get("hmac_secret", "secret")
                    manipulator = JWTManipulator(original_token)
                    result = manipulator.sign_with_hs_secret(
                        secret,
                        algorithm="HS256",
                        key_description="HMAC secret (algorithm confusion test)",
                    )

            except ValueError as e:
                error = str(e)
            except KeyError as e:
                error = str(e)
            except Exception as e:
                error = f"Error processing token: {e}"

    # Get stored signing key if available
    signing_key = session.get(JWT_SIGNING_KEY_SESSION)

    return render_template(
        "tools/jwt.html",
        original_token=original_token,
        decoded_token=decoded_token,
        result=result,
        error=error,
        signing_key=signing_key,
    )


@tools_bp.route("/saml", methods=["GET", "POST"])
def saml_manipulator() -> str:
    """SAML assertion manipulation tool."""
    result = None
    error = None
    parsed_info = None
    original_xml = ""

    if request.method == "POST":
        original_xml = request.form.get("saml_xml", "").strip()
        action = request.form.get("action", "parse")

        if not original_xml:
            error = "Please provide a SAML Response or Assertion"
        else:
            try:
                # Parse basic info first
                nameid, nameid_format = get_nameid_from_assertion(original_xml)
                attributes = parse_saml_attributes(original_xml)
                parsed_info = {
                    "nameid": nameid,
                    "nameid_format": nameid_format,
                    "attributes": attributes,
                }

                if action == "parse":
                    # Just parse, no manipulation
                    pass

                elif action == "strip_signature":
                    # Strip signatures
                    manipulator = SAMLManipulator(original_xml)
                    result = manipulator.strip_signature()

                elif action == "modify_nameid":
                    # Modify NameID
                    new_nameid = request.form.get("new_nameid", "")
                    if not new_nameid:
                        error = "Please provide a new NameID value"
                    else:
                        manipulator = SAMLManipulator(original_xml)
                        manipulator.modify_nameid(new_nameid)

                        sign_method = request.form.get("sign_method", "unsigned")
                        if sign_method == "strip":
                            result = manipulator.strip_signature()
                        else:
                            result = manipulator.build_unsigned()

                elif action == "extend_validity":
                    # Extend validity period
                    hours = int(request.form.get("extend_hours", 24))
                    manipulator = SAMLManipulator(original_xml)
                    manipulator.extend_conditions(hours=hours)

                    sign_method = request.form.get("sign_method", "unsigned")
                    if sign_method == "strip":
                        result = manipulator.strip_signature()
                    else:
                        result = manipulator.build_unsigned()

                elif action == "modify_attributes":
                    # Modify attributes
                    manipulator = SAMLManipulator(original_xml)

                    # Modify issuer if provided
                    new_issuer = request.form.get("new_issuer")
                    if new_issuer:
                        manipulator.modify_issuer(new_issuer)

                    # Modify audience if provided
                    new_audience = request.form.get("new_audience")
                    if new_audience:
                        manipulator.modify_audience(new_audience)

                    # Add/modify custom attribute
                    attr_name = request.form.get("attr_name")
                    attr_value = request.form.get("attr_value")
                    if attr_name and attr_value:
                        # Handle multiple values (comma-separated)
                        values = [v.strip() for v in attr_value.split(",")]
                        manipulator.modify_attribute(attr_name, values, create_if_missing=True)

                    # Add role/group attribute
                    new_role = request.form.get("new_role")
                    if new_role:
                        manipulator.add_attribute(
                            "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
                            new_role,
                            friendly_name="role",
                        )

                    sign_method = request.form.get("sign_method", "unsigned")
                    if sign_method == "strip":
                        result = manipulator.strip_signature()
                    else:
                        result = manipulator.build_unsigned()

            except ValueError as e:
                error = str(e)
            except Exception as e:
                error = f"Error processing SAML: {e}"

    return render_template(
        "tools/saml.html",
        original_xml=original_xml,
        parsed_info=parsed_info,
        result=result,
        error=error,
    )


@tools_bp.route("/generate-key", methods=["POST"])
def generate_key() -> str:
    """Generate a new signing key pair."""
    algorithm = request.form.get("algorithm", "RS256")
    key_size = int(request.form.get("key_size", 2048))

    try:
        private_key, public_key, key_id = generate_signing_key_pair(algorithm, key_size)

        key_info = {
            "key_id": key_id,
            "algorithm": algorithm,
            "private_key_pem": get_private_key_pem(private_key),
            "public_key_pem": get_public_key_pem(public_key),
            "jwk": get_public_key_jwk(public_key, key_id, algorithm),
        }

        session[JWT_SIGNING_KEY_SESSION] = key_info

        return render_template("tools/key_generated.html", key_info=key_info)

    except Exception as e:
        flash(f"Error generating key: {e}", "error")
        return render_template("tools/key_generated.html", error=str(e))
