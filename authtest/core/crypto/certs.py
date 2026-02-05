"""Certificate management utilities.

Provides self-signed certificate generation, loading from PEM/PKCS12 formats,
and certificate validation/inspection.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

# Default paths for TLS certificates
DEFAULT_CERT_DIR = Path.home() / ".authtest" / "certs"
DEFAULT_CERT_PATH = DEFAULT_CERT_DIR / "server.crt"
DEFAULT_KEY_PATH = DEFAULT_CERT_DIR / "server.key"

# Environment variables
ENV_TLS_CERT = "AUTHTEST_TLS_CERT"
ENV_TLS_KEY = "AUTHTEST_TLS_KEY"
ENV_TLS_CERT_DIR = "AUTHTEST_TLS_CERT_DIR"


class CertificateError(Exception):
    """Base exception for certificate-related errors."""


class CertificateNotFoundError(CertificateError):
    """Raised when a certificate file is not found."""


class CertificateLoadError(CertificateError):
    """Raised when a certificate cannot be loaded."""


class KeyLoadError(CertificateError):
    """Raised when a private key cannot be loaded."""


@dataclass
class CertificateInfo:
    """Information extracted from an X.509 certificate."""

    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    fingerprint_sha256: str
    is_self_signed: bool
    key_type: str
    key_size: int


@dataclass
class TLSConfig:
    """TLS configuration for the server."""

    cert_path: Path
    key_path: Path
    enabled: bool = True
    auto_generated: bool = False

    @property
    def exists(self) -> bool:
        """Check if both certificate and key files exist."""
        return self.cert_path.exists() and self.key_path.exists()


def get_cert_dir() -> Path:
    """Get the certificate directory from environment or default.

    Returns:
        Path to the certificate directory.
    """
    env_dir = os.environ.get(ENV_TLS_CERT_DIR)
    if env_dir:
        return Path(env_dir)
    return DEFAULT_CERT_DIR


def get_cert_path() -> Path:
    """Get the TLS certificate path from environment or default.

    Returns:
        Path to the certificate file.
    """
    env_path = os.environ.get(ENV_TLS_CERT)
    if env_path:
        return Path(env_path)
    return get_cert_dir() / "server.crt"


def get_key_path() -> Path:
    """Get the TLS private key path from environment or default.

    Returns:
        Path to the private key file.
    """
    env_path = os.environ.get(ENV_TLS_KEY)
    if env_path:
        return Path(env_path)
    return get_cert_dir() / "server.key"


def generate_private_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """Generate an RSA private key.

    Args:
        key_size: RSA key size in bits. Default 2048.

    Returns:
        RSA private key.
    """
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )


def generate_self_signed_certificate(
    private_key: rsa.RSAPrivateKey,
    common_name: str = "localhost",
    organization: str = "AuthTest",
    days_valid: int = 365,
    san_dns_names: list[str] | None = None,
    san_ip_addresses: list[str] | None = None,
) -> x509.Certificate:
    """Generate a self-signed X.509 certificate.

    Args:
        private_key: RSA private key to sign the certificate.
        common_name: Common Name (CN) for the certificate subject.
        organization: Organization (O) for the certificate subject.
        days_valid: Number of days the certificate is valid.
        san_dns_names: Additional DNS names for Subject Alternative Name.
        san_ip_addresses: IP addresses for Subject Alternative Name.

    Returns:
        Self-signed X.509 certificate.
    """
    from ipaddress import ip_address

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.now(UTC)
    not_before = now
    not_after = now + timedelta(days=days_valid)

    # Build Subject Alternative Names
    san_entries: list[x509.GeneralName] = [
        x509.DNSName(common_name),
    ]

    # Add localhost variants by default for development
    if common_name != "localhost":
        san_entries.append(x509.DNSName("localhost"))

    # Add additional DNS names
    if san_dns_names:
        for name in san_dns_names:
            if name not in [common_name, "localhost"]:
                san_entries.append(x509.DNSName(name))

    # Add IP addresses (localhost by default)
    san_entries.append(x509.IPAddress(ip_address("127.0.0.1")))
    san_entries.append(x509.IPAddress(ip_address("::1")))

    if san_ip_addresses:
        for ip_str in san_ip_addresses:
            ip_obj = ip_address(ip_str)
            if ip_str not in ["127.0.0.1", "::1"]:
                san_entries.append(x509.IPAddress(ip_obj))

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    return cert


def save_private_key(
    private_key: rsa.RSAPrivateKey,
    path: Path,
    password: bytes | None = None,
) -> None:
    """Save a private key to a PEM file with secure permissions.

    Args:
        private_key: RSA private key to save.
        path: Path to write the key file.
        password: Optional password to encrypt the key.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )

    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )

    # Write with restricted permissions (0600)
    path.touch(mode=0o600)
    path.write_bytes(pem_data)
    # Ensure permissions are correct even if file existed
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def save_certificate(cert: x509.Certificate, path: Path) -> None:
    """Save a certificate to a PEM file.

    Args:
        cert: X.509 certificate to save.
        path: Path to write the certificate file.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    pem_data = cert.public_bytes(serialization.Encoding.PEM)
    path.write_bytes(pem_data)


def load_private_key(
    path: Path,
    password: bytes | None = None,
) -> rsa.RSAPrivateKey:
    """Load a private key from a PEM file.

    Args:
        path: Path to the key file.
        password: Optional password if key is encrypted.

    Returns:
        RSA private key.

    Raises:
        KeyLoadError: If the key cannot be loaded.
    """
    if not path.exists():
        raise KeyLoadError(f"Private key file not found: {path}")

    try:
        pem_data = path.read_bytes()
        key = serialization.load_pem_private_key(pem_data, password=password)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise KeyLoadError(f"Expected RSA private key, got {type(key).__name__}")
        return key
    except Exception as e:
        if isinstance(e, KeyLoadError):
            raise
        raise KeyLoadError(f"Failed to load private key from {path}: {e}") from e


def load_certificate(path: Path) -> x509.Certificate:
    """Load a certificate from a PEM file.

    Args:
        path: Path to the certificate file.

    Returns:
        X.509 certificate.

    Raises:
        CertificateLoadError: If the certificate cannot be loaded.
    """
    if not path.exists():
        raise CertificateLoadError(f"Certificate file not found: {path}")

    try:
        pem_data = path.read_bytes()
        return x509.load_pem_x509_certificate(pem_data)
    except Exception as e:
        if isinstance(e, CertificateLoadError):
            raise
        raise CertificateLoadError(f"Failed to load certificate from {path}: {e}") from e


def load_pkcs12(
    path: Path,
    password: bytes | None = None,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate, list[x509.Certificate]]:
    """Load a PKCS#12 file containing certificate and private key.

    Args:
        path: Path to the PKCS#12 file.
        password: Password for the PKCS#12 file (often required).

    Returns:
        Tuple of (private_key, certificate, additional_certificates).

    Raises:
        CertificateLoadError: If the file cannot be loaded.
    """
    if not path.exists():
        raise CertificateLoadError(f"PKCS#12 file not found: {path}")

    try:
        p12_data = path.read_bytes()
        private_key, cert, chain = pkcs12.load_key_and_certificates(p12_data, password)

        if private_key is None:
            raise CertificateLoadError("PKCS#12 file does not contain a private key")
        if cert is None:
            raise CertificateLoadError("PKCS#12 file does not contain a certificate")
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise CertificateLoadError(
                f"Expected RSA private key, got {type(private_key).__name__}"
            )

        additional_certs = list(chain) if chain else []
        return private_key, cert, additional_certs

    except Exception as e:
        if isinstance(e, CertificateLoadError):
            raise
        raise CertificateLoadError(f"Failed to load PKCS#12 from {path}: {e}") from e


def get_certificate_info(cert: x509.Certificate) -> CertificateInfo:
    """Extract information from an X.509 certificate.

    Args:
        cert: X.509 certificate.

    Returns:
        CertificateInfo with extracted details.
    """
    # Get subject and issuer as strings
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()

    # Check if self-signed
    is_self_signed = cert.subject == cert.issuer

    # Get fingerprint
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()

    # Get key info
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        key_type = "RSA"
        key_size = public_key.key_size
    else:
        key_type = type(public_key).__name__
        key_size = 0

    return CertificateInfo(
        subject=subject,
        issuer=issuer,
        serial_number=format(cert.serial_number, "x"),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        fingerprint_sha256=fingerprint,
        is_self_signed=is_self_signed,
        key_type=key_type,
        key_size=key_size,
    )


def is_certificate_valid(cert: x509.Certificate) -> bool:
    """Check if a certificate is currently valid (not expired).

    Args:
        cert: X.509 certificate to check.

    Returns:
        True if certificate is valid, False otherwise.
    """
    now = datetime.now(UTC)
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def ensure_tls_certificate(
    cert_path: Path | None = None,
    key_path: Path | None = None,
    common_name: str = "localhost",
    days_valid: int = 365,
    regenerate: bool = False,
) -> TLSConfig:
    """Ensure TLS certificate exists, generating one if needed.

    This is the main entry point for automatic certificate setup on first run.
    It will generate a self-signed certificate if none exists.

    Args:
        cert_path: Path to certificate file. Uses default if not specified.
        key_path: Path to key file. Uses default if not specified.
        common_name: Common name for generated certificate.
        days_valid: Days the generated certificate is valid.
        regenerate: Force regeneration even if certificate exists.

    Returns:
        TLSConfig with paths and auto_generated flag.
    """
    cert_path = cert_path or get_cert_path()
    key_path = key_path or get_key_path()

    auto_generated = False

    # Check if we need to generate
    if regenerate or not cert_path.exists() or not key_path.exists():
        # Generate new certificate
        private_key = generate_private_key()
        cert = generate_self_signed_certificate(
            private_key,
            common_name=common_name,
            days_valid=days_valid,
        )

        save_private_key(private_key, key_path)
        save_certificate(cert, cert_path)
        auto_generated = True
    else:
        # Check if existing certificate is still valid
        try:
            cert = load_certificate(cert_path)
            if not is_certificate_valid(cert):
                # Regenerate expired certificate
                private_key = generate_private_key()
                cert = generate_self_signed_certificate(
                    private_key,
                    common_name=common_name,
                    days_valid=days_valid,
                )
                save_private_key(private_key, key_path)
                save_certificate(cert, cert_path)
                auto_generated = True
        except CertificateLoadError:
            # Certificate exists but can't be loaded, regenerate
            private_key = generate_private_key()
            cert = generate_self_signed_certificate(
                private_key,
                common_name=common_name,
                days_valid=days_valid,
            )
            save_private_key(private_key, key_path)
            save_certificate(cert, cert_path)
            auto_generated = True

    return TLSConfig(
        cert_path=cert_path,
        key_path=key_path,
        enabled=True,
        auto_generated=auto_generated,
    )


def get_private_key_pem(private_key: rsa.RSAPrivateKey, password: bytes | None = None) -> str:
    """Get PEM-encoded string of a private key.

    Args:
        private_key: RSA private key.
        password: Optional password for encryption.

    Returns:
        PEM-encoded private key string.
    """
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    ).decode("utf-8")


def get_certificate_pem(cert: x509.Certificate) -> str:
    """Get PEM-encoded string of a certificate.

    Args:
        cert: X.509 certificate.

    Returns:
        PEM-encoded certificate string.
    """
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def compute_certificate_fingerprint(cert_pem: str, algorithm: str = "sha256") -> str:
    """Compute fingerprint of a PEM-encoded certificate.

    Args:
        cert_pem: PEM-encoded certificate string.
        algorithm: Hash algorithm to use (sha256, sha1, md5).

    Returns:
        Hex-encoded fingerprint.
    """
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))

    if algorithm == "sha256":
        return cert.fingerprint(hashes.SHA256()).hex()
    elif algorithm == "sha1":
        return cert.fingerprint(hashes.SHA1()).hex()  # noqa: S303
    elif algorithm == "md5":
        return cert.fingerprint(hashes.MD5()).hex()  # noqa: S303
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
