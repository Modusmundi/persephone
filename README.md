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

## Installation

### Development Setup

```bash
# Clone the repository
git clone https://github.com/authtest/authtest.git
cd authtest

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install with development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run type checking
mypy authtest

# Run linting
ruff check authtest
```

### Docker

```bash
cd docker
docker-compose up -d
```

## Usage

### CLI

```bash
# Initialize configuration
authtest init

# Add an IdP configuration
authtest config idp add my-keycloak

# Run a SAML test
authtest test saml sp-initiated --idp my-keycloak

# Run an OIDC test
authtest test oidc authorization-code --idp my-keycloak

# Manage certificates
authtest certs generate --type tls
authtest certs list
```

### Web UI

```bash
# Start the web server
python -m authtest

# Open browser to https://localhost:8443
```

## Configuration

Configuration is stored in `~/.authtest/` by default:

- `config.yaml` - Application settings
- `data.db` - Encrypted SQLite database
- `logs/` - Application logs

### Environment Variables

- `APP_DB_KEY` - Database encryption key
- `FLASK_ENV` - Flask environment (development/production)

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
└── pyproject.toml      # Project metadata
```

## License

MIT License
