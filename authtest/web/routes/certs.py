"""Certificate management routes."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from flask import (
    Blueprint,
    Response,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

if TYPE_CHECKING:
    from werkzeug.wrappers import Response as WerkzeugResponse

from authtest.core.crypto import (
    DEFAULT_CERT_DIR,
    CertificateLoadError,
    generate_private_key,
    generate_self_signed_certificate,
    get_certificate_info,
    get_certificate_pem,
    is_certificate_valid,
    load_certificate,
    save_certificate,
    save_private_key,
)

# Get the directories relative to this package
_web_dir = Path(__file__).parent.parent
_templates_dir = _web_dir / "templates"

certs_bp = Blueprint(
    "certs",
    __name__,
    template_folder=str(_templates_dir),
    url_prefix="/certs",
)


def get_cert_dir() -> Path:
    """Get the certificate directory."""
    cert_dir = DEFAULT_CERT_DIR
    cert_dir.mkdir(parents=True, exist_ok=True)
    return cert_dir


def list_certificates() -> list[dict]:
    """List all certificates in the certificate directory.

    Returns:
        List of certificate info dicts with name, info, valid status, and has_key flag.
    """
    cert_dir = get_cert_dir()
    certs = []

    # Find all .crt and .pem files
    cert_files = list(cert_dir.glob("*.crt")) + list(cert_dir.glob("*.pem"))

    for cert_file in sorted(cert_files):
        try:
            cert = load_certificate(cert_file)
            info = get_certificate_info(cert)
            valid = is_certificate_valid(cert)

            # Check if corresponding key exists
            key_path = cert_file.with_suffix(".key")
            has_key = key_path.exists()

            certs.append({
                "name": cert_file.stem,
                "filename": cert_file.name,
                "path": str(cert_file),
                "info": info,
                "valid": valid,
                "has_key": has_key,
            })
        except CertificateLoadError:
            certs.append({
                "name": cert_file.stem,
                "filename": cert_file.name,
                "path": str(cert_file),
                "info": None,
                "valid": False,
                "has_key": False,
                "error": "Could not load certificate",
            })

    return certs


@certs_bp.route("/")
def index() -> str:
    """Certificate management home page."""
    certs = list_certificates()
    return render_template("certs/index.html", certs=certs, cert_dir=get_cert_dir())


@certs_bp.route("/generate", methods=["GET", "POST"])
def generate() -> str | WerkzeugResponse:
    """Generate a new self-signed certificate."""
    if request.method == "GET":
        return render_template("certs/generate.html")

    # POST - generate certificate
    cert_type = request.form.get("cert_type", "signing")
    common_name = request.form.get("common_name", "localhost")
    organization = request.form.get("organization", "AuthTest")
    days_valid = int(request.form.get("days_valid", "365"))
    name = request.form.get("name", "")

    if not name:
        name = "signing" if cert_type == "signing" else "server"

    # Validate inputs
    if days_valid < 1 or days_valid > 3650:
        flash("Days valid must be between 1 and 3650", "error")
        return render_template("certs/generate.html")

    cert_dir = get_cert_dir()
    cert_path = cert_dir / f"{name}.crt"
    key_path = cert_dir / f"{name}.key"

    # Check for existing files
    if cert_path.exists() or key_path.exists():
        force = request.form.get("force") == "on"
        if not force:
            flash(
                f"Certificate '{name}' already exists. Check 'Overwrite' to replace it.",
                "error",
            )
            return render_template("certs/generate.html")

    try:
        # Generate key and certificate
        private_key = generate_private_key()
        cert = generate_self_signed_certificate(
            private_key,
            common_name=common_name,
            organization=organization,
            days_valid=days_valid,
        )

        # Save files
        save_private_key(private_key, key_path)
        save_certificate(cert, cert_path)

        flash(f"Certificate '{name}' generated successfully!", "success")
        return redirect(url_for("certs.view", name=name))

    except Exception as e:
        flash(f"Failed to generate certificate: {e}", "error")
        return render_template("certs/generate.html")


@certs_bp.route("/import", methods=["GET", "POST"])
def import_cert() -> str | WerkzeugResponse:
    """Import an existing certificate."""
    if request.method == "GET":
        return render_template("certs/import.html")

    # POST - import certificate
    name = request.form.get("name", "imported")
    password = request.form.get("password", "")
    password_bytes = password.encode() if password else None

    cert_file = request.files.get("cert_file")
    key_file = request.files.get("key_file")

    if not cert_file:
        flash("Certificate file is required", "error")
        return render_template("certs/import.html")

    cert_dir = get_cert_dir()
    cert_path = cert_dir / f"{name}.crt"
    key_path = cert_dir / f"{name}.key"

    # Check for existing files
    if cert_path.exists() or key_path.exists():
        force = request.form.get("force") == "on"
        if not force:
            flash(
                f"Certificate '{name}' already exists. Check 'Overwrite' to replace it.",
                "error",
            )
            return render_template("certs/import.html")

    # Read certificate content
    cert_content = cert_file.read()
    filename = cert_file.filename or ""

    try:
        # Detect format by extension or content
        is_pkcs12 = filename.lower().endswith((".p12", ".pfx"))

        if is_pkcs12:
            # PKCS#12 format - contains both cert and key
            from cryptography.hazmat.primitives.serialization import pkcs12

            private_key, cert, chain = pkcs12.load_key_and_certificates(
                cert_content, password_bytes
            )

            if private_key is None:
                flash("PKCS#12 file does not contain a private key", "error")
                return render_template("certs/import.html")
            if cert is None:
                flash("PKCS#12 file does not contain a certificate", "error")
                return render_template("certs/import.html")

            # Save files
            from cryptography.hazmat.primitives.asymmetric import rsa

            if not isinstance(private_key, rsa.RSAPrivateKey):
                flash(
                    f"Expected RSA private key, got {type(private_key).__name__}",
                    "error",
                )
                return render_template("certs/import.html")

            save_private_key(private_key, key_path)
            save_certificate(cert, cert_path)

            # Save chain if present
            if chain:
                chain_path = cert_dir / f"{name}-chain.crt"
                from cryptography.hazmat.primitives import serialization

                chain_pem = b""
                for chain_cert in chain:
                    chain_pem += chain_cert.public_bytes(serialization.Encoding.PEM)
                chain_path.write_bytes(chain_pem)

            flash(f"PKCS#12 certificate '{name}' imported successfully!", "success")

        else:
            # PEM format
            from cryptography import x509

            cert = x509.load_pem_x509_certificate(cert_content)
            save_certificate(cert, cert_path)

            # Import key if provided
            if key_file:
                key_content = key_file.read()
                from cryptography.hazmat.primitives import serialization

                private_key = serialization.load_pem_private_key(
                    key_content, password=password_bytes
                )
                from cryptography.hazmat.primitives.asymmetric import rsa

                if not isinstance(private_key, rsa.RSAPrivateKey):
                    flash(
                        f"Expected RSA private key, got {type(private_key).__name__}",
                        "error",
                    )
                    return render_template("certs/import.html")
                save_private_key(private_key, key_path)

            flash(f"Certificate '{name}' imported successfully!", "success")

        return redirect(url_for("certs.view", name=name))

    except Exception as e:
        flash(f"Failed to import certificate: {e}", "error")
        return render_template("certs/import.html")


@certs_bp.route("/view/<name>")
def view(name: str) -> str | WerkzeugResponse:
    """View certificate details."""
    cert_dir = get_cert_dir()
    cert_path = cert_dir / f"{name}.crt"

    if not cert_path.exists():
        flash(f"Certificate '{name}' not found", "error")
        return redirect(url_for("certs.index"))

    try:
        cert = load_certificate(cert_path)
        info = get_certificate_info(cert)
        valid = is_certificate_valid(cert)
        pem = get_certificate_pem(cert)

        # Check for key
        key_path = cert_path.with_suffix(".key")
        has_key = key_path.exists()

        # Get SANs
        from cryptography import x509 as x509_mod

        sans = []
        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509_mod.SubjectAlternativeName
            )
            for san_name in san_ext.value:
                if isinstance(san_name, x509_mod.DNSName):
                    sans.append({"type": "DNS", "value": san_name.value})
                elif isinstance(san_name, x509_mod.IPAddress):
                    sans.append({"type": "IP", "value": str(san_name.value)})
        except x509_mod.ExtensionNotFound:
            pass

        # Get key usage
        key_usage = []
        try:
            ku_ext = cert.extensions.get_extension_for_class(x509_mod.KeyUsage)
            ku = ku_ext.value
            if ku.digital_signature:
                key_usage.append("Digital Signature")
            if ku.key_encipherment:
                key_usage.append("Key Encipherment")
            if ku.key_cert_sign:
                key_usage.append("Certificate Sign")
            if ku.crl_sign:
                key_usage.append("CRL Sign")
            if ku.content_commitment:
                key_usage.append("Content Commitment")
            if ku.data_encipherment:
                key_usage.append("Data Encipherment")
            if ku.key_agreement:
                key_usage.append("Key Agreement")
        except x509_mod.ExtensionNotFound:
            pass

        # Get extended key usage
        ext_key_usage = []
        try:
            eku_ext = cert.extensions.get_extension_for_class(x509_mod.ExtendedKeyUsage)
            for oid in eku_ext.value:
                if oid == x509_mod.oid.ExtendedKeyUsageOID.SERVER_AUTH:
                    ext_key_usage.append("Server Authentication")
                elif oid == x509_mod.oid.ExtendedKeyUsageOID.CLIENT_AUTH:
                    ext_key_usage.append("Client Authentication")
                elif oid == x509_mod.oid.ExtendedKeyUsageOID.CODE_SIGNING:
                    ext_key_usage.append("Code Signing")
                elif oid == x509_mod.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION:
                    ext_key_usage.append("Email Protection")
                else:
                    ext_key_usage.append(oid.dotted_string)
        except x509_mod.ExtensionNotFound:
            pass

        # Check if certificate chain exists
        chain_path = cert_dir / f"{name}-chain.crt"
        has_chain = chain_path.exists()

        return render_template(
            "certs/view.html",
            name=name,
            info=info,
            valid=valid,
            pem=pem,
            has_key=has_key,
            has_chain=has_chain,
            sans=sans,
            key_usage=key_usage,
            ext_key_usage=ext_key_usage,
        )

    except CertificateLoadError as e:
        flash(f"Failed to load certificate: {e}", "error")
        return redirect(url_for("certs.index"))


@certs_bp.route("/download/<name>")
def download(name: str) -> Response | WerkzeugResponse:
    """Download certificate as PEM file."""
    cert_dir = get_cert_dir()
    cert_path = cert_dir / f"{name}.crt"

    if not cert_path.exists():
        flash(f"Certificate '{name}' not found", "error")
        return redirect(url_for("certs.index"))

    try:
        cert = load_certificate(cert_path)
        pem = get_certificate_pem(cert)

        response: Response = current_app.make_response(pem)
        response.headers["Content-Type"] = "application/x-pem-file"
        response.headers["Content-Disposition"] = f'attachment; filename="{name}.crt"'
        return response

    except CertificateLoadError as e:
        flash(f"Failed to load certificate: {e}", "error")
        return redirect(url_for("certs.index"))


@certs_bp.route("/delete/<name>", methods=["POST"])
def delete(name: str) -> WerkzeugResponse:
    """Delete a certificate and its key."""
    cert_dir = get_cert_dir()
    cert_path = cert_dir / f"{name}.crt"
    key_path = cert_dir / f"{name}.key"
    chain_path = cert_dir / f"{name}-chain.crt"

    deleted = []

    if cert_path.exists():
        cert_path.unlink()
        deleted.append("certificate")

    if key_path.exists():
        key_path.unlink()
        deleted.append("private key")

    if chain_path.exists():
        chain_path.unlink()
        deleted.append("chain")

    if deleted:
        flash(f"Deleted {', '.join(deleted)} for '{name}'", "success")
    else:
        flash(f"Certificate '{name}' not found", "error")

    return redirect(url_for("certs.index"))


@certs_bp.route("/validate/<name>")
def validate(name: str) -> str | WerkzeugResponse:
    """Validate certificate chain."""
    cert_dir = get_cert_dir()
    cert_path = cert_dir / f"{name}.crt"
    chain_path = cert_dir / f"{name}-chain.crt"

    if not cert_path.exists():
        flash(f"Certificate '{name}' not found", "error")
        return redirect(url_for("certs.index"))

    try:
        cert = load_certificate(cert_path)
        info = get_certificate_info(cert)

        validation_results = []

        # Check validity period
        valid = is_certificate_valid(cert)
        validation_results.append({
            "check": "Validity Period",
            "passed": valid,
            "message": (
                "Certificate is currently valid"
                if valid
                else f"Certificate expired on {info.not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}"
            ),
        })

        # Check self-signed
        is_self_signed = info.is_self_signed
        validation_results.append({
            "check": "Self-Signed",
            "passed": None,  # Neutral - informational
            "message": (
                "Certificate is self-signed (subject equals issuer)"
                if is_self_signed
                else "Certificate was issued by a different CA"
            ),
        })

        # Check key size
        min_key_size = 2048
        key_ok = info.key_size >= min_key_size
        validation_results.append({
            "check": "Key Size",
            "passed": key_ok,
            "message": (
                f"{info.key_type} {info.key_size}-bit key meets minimum requirements"
                if key_ok
                else f"{info.key_type} {info.key_size}-bit key is below recommended {min_key_size} bits"
            ),
        })

        # Check chain if present
        if chain_path.exists():
            try:
                chain_data = chain_path.read_bytes()
                from cryptography import x509 as x509_mod

                chain_certs = []
                pem_start = b"-----BEGIN CERTIFICATE-----"
                pem_end = b"-----END CERTIFICATE-----"

                # Parse multiple certificates from chain file
                remaining = chain_data
                while pem_start in remaining:
                    start_idx = remaining.index(pem_start)
                    end_idx = remaining.index(pem_end) + len(pem_end)
                    cert_pem = remaining[start_idx:end_idx]
                    chain_certs.append(x509_mod.load_pem_x509_certificate(cert_pem))
                    remaining = remaining[end_idx:]

                # Verify chain
                for i, chain_cert in enumerate(chain_certs):
                    chain_info = get_certificate_info(chain_cert)
                    if not is_certificate_valid(chain_cert):
                        validation_results.append({
                            "check": f"Chain Certificate {i + 1}",
                            "passed": False,
                            "message": f"Chain certificate '{chain_info.subject}' is expired",
                        })
                    else:
                        validation_results.append({
                            "check": f"Chain Certificate {i + 1}",
                            "passed": True,
                            "message": f"Chain certificate '{chain_info.subject}' is valid",
                        })

            except Exception as e:
                validation_results.append({
                    "check": "Certificate Chain",
                    "passed": False,
                    "message": f"Failed to parse chain: {e}",
                })
        else:
            validation_results.append({
                "check": "Certificate Chain",
                "passed": None,
                "message": "No certificate chain file found",
            })

        return render_template(
            "certs/validate.html",
            name=name,
            info=info,
            results=validation_results,
        )

    except CertificateLoadError as e:
        flash(f"Failed to load certificate: {e}", "error")
        return redirect(url_for("certs.index"))
