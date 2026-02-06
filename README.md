# AuthTest

SAML/OIDC Authentication Flow Testing Application

## Overview

AuthTest is a comprehensive testing tool for SAML and OIDC authentication flows. It provides both a web UI and CLI interface for security professionals and developers to test authentication integrations.

## Features

- **SAML Support**: SP-Initiated SSO, IdP-Initiated SSO, Single Logout
- **OIDC Support**: Authorization Code, PKCE, Implicit, Client Credentials, Device Code
- **IdP Presets**: Keycloak, Okta, Azure AD, Auth0, Google Workspace, and more
- **Secure Storage**: SQLCipher encrypted database for sensitive configuration
- **Protocol Inspection**: Full request/response logging with token/assertion decoding
- **Report Generation**: JSON, PDF, and HTML export formats

## Requirements

- Python 3.11+
- For PDF export: WeasyPrint dependencies (pango, cairo)

## Quick Start

### 1. Install AuthTest

```bash
# Clone the repository
git clone https://github.com/authtest/authtest.git
cd authtest

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install the package
pip install -e .
```

### 2. Initialize Configuration

```bash
# Initialize the encrypted database and generate encryption key
authtest init
```

This creates:
- `~/.authtest/authtest.db` - Encrypted SQLCipher database
- `~/.authtest/db.key` - AES-256 encryption key (keep this safe!)

### 3. Add an Identity Provider

**Option A: Using a preset (recommended for Keycloak)**

```bash
# Add Keycloak with SAML
authtest config idp from-preset my-keycloak \
    --preset keycloak \
    --base-url https://keycloak.example.com \
    --realm myrealm

# Add Keycloak with OIDC
authtest config idp from-preset my-keycloak-oidc \
    --preset keycloak \
    --type oidc \
    --base-url https://keycloak.example.com \
    --realm myrealm
```

**Option B: Manual configuration**

```bash
# Interactive mode - prompts for all values
authtest config idp add my-okta -i

# Non-interactive SAML configuration
authtest config idp add my-saml --type saml \
    --entity-id https://idp.example.com \
    --sso-url https://idp.example.com/sso
```

### 4. Run Authentication Tests

```bash
# Test SAML SP-Initiated SSO
authtest test saml sp-initiated --idp my-keycloak

# Test OIDC Authorization Code flow
authtest test oidc authorization-code --idp my-keycloak-oidc

# Test OIDC with PKCE
authtest test oidc authorization-code-pkce --idp my-keycloak-oidc
```

### 5. Start the Web Interface

```bash
# Start web server with auto-generated TLS certificate
authtest serve

# Open browser to https://localhost:8443
```

## Documentation

- [CLI Command Reference](docs/cli-reference.md) - Complete CLI documentation
- [Web UI Guide](docs/web-ui-guide.md) - Web interface user guide
- [IdP Setup Guides](docs/idp-setup/) - Setup guides for each IdP preset
  - [Keycloak](docs/idp-setup/keycloak.md)

## Configuration

Configuration is stored in `~/.authtest/` by default:

- `config.yaml` - Application settings
- `authtest.db` - Encrypted SQLite database
- `db.key` - Database encryption key
- `certs/` - TLS and signing certificates
- `logs/` - Application logs

### Environment Variables

| Variable | Description |
|----------|-------------|
| `AUTHTEST_DB_KEY` | Database encryption key (alternative to key file) |
| `AUTHTEST_CONFIG_DIR` | Configuration directory (default: `~/.authtest`) |
| `FLASK_ENV` | Flask environment (development/production) |

### Sample config.yaml

```yaml
server:
  host: 0.0.0.0
  port: 8443
  tls:
    enabled: true
    auto_generate: true
    cert_path: null  # Uses auto-generated if null
    key_path: null

database:
  path: ~/.authtest/authtest.db

security:
  password_required: true
  session_timeout: 3600

logging:
  level: INFO
  file: ~/.authtest/logs/app.log
```

## Project Structure

```
authtest/
├── authtest/           # Main package
│   ├── cli/            # CLI commands
│   ├── web/            # Web UI (Flask + HTMX)
│   ├── core/           # Auth flow implementations
│   │   ├── saml/       # SAML flows
│   │   ├── oidc/       # OIDC flows
│   │   └── crypto/     # Certificate/token handling
│   ├── storage/        # Database layer
│   ├── idp_presets/    # IdP configurations
│   └── reports/        # Report generators
├── tests/              # Test suite
├── docker/             # Docker configuration
├── docs/               # Documentation
└── pyproject.toml      # Project metadata
```

## Development

```bash
# Install with development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run type checking
mypy authtest

# Run linting
ruff check authtest
```

## Docker

```bash
cd docker
docker-compose up -d

# Access at https://localhost:8443
```

## Security Notes

1. **Encryption Key**: The database encryption key (`~/.authtest/db.key`) provides AES-256 encryption for all stored data including client secrets and certificates. Keep this file secure and backed up.

2. **TLS**: The web interface runs with HTTPS by default. A self-signed certificate is auto-generated if none is provided. For production use, configure a proper TLS certificate.

3. **Password Protection**: Application access can be password-protected. Configure via the web UI or CLI.

## License

MIT License
