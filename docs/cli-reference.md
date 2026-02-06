# AuthTest CLI Command Reference

Complete reference for all AuthTest command-line interface commands.

## Global Options

All commands support:
- `--version` - Show version and exit
- `--help` - Show help message and exit

## Commands Overview

| Command | Description |
|---------|-------------|
| `authtest init` | Initialize AuthTest (shortcut for `db init`) |
| `authtest serve` | Start the web server |
| `authtest config` | Manage configuration |
| `authtest test` | Execute authentication tests |
| `authtest certs` | Manage TLS certificates |
| `authtest db` | Manage database |

---

## authtest init

Initialize AuthTest configuration and database.

```bash
authtest init [OPTIONS]
```

### Options

| Option | Description |
|--------|-------------|
| `--force` | Overwrite existing database and key files |

### Examples

```bash
# Initialize with default paths
authtest init

# Force reinitialize (deletes existing data)
authtest init --force
```

---

## authtest serve

Start the AuthTest web server.

```bash
authtest serve [OPTIONS]
```

### Options

| Option | Description |
|--------|-------------|
| `-h, --host TEXT` | Host to bind to (default: from config or 127.0.0.1) |
| `-p, --port INTEGER` | Port to bind to (default: from config or 8443) |
| `--no-tls` | Disable TLS (not recommended, required for OIDC) |
| `--cert PATH` | Path to TLS certificate (PEM format) |
| `--key PATH` | Path to TLS private key (PEM format) |
| `--debug` | Enable debug mode |

### Examples

```bash
# Start with auto-generated certificate
authtest serve

# Start on custom port
authtest serve --port 9443

# Use custom certificate
authtest serve --cert /path/to/cert.pem --key /path/to/key.pem

# Disable TLS (not recommended)
authtest serve --no-tls
```

---

## authtest config

Manage AuthTest configuration.

### authtest config init

Initialize configuration database.

```bash
authtest config init [OPTIONS]
```

#### Options

| Option | Description |
|--------|-------------|
| `--force` | Overwrite existing database and key files |
| `--json` | Output results as JSON for scripting |

#### Examples

```bash
# Initialize with default paths
authtest config init

# Force reinitialize
authtest config init --force

# JSON output for scripting
authtest config init --json
```

---

### authtest config idp

Manage Identity Provider configurations.

#### authtest config idp add

Add a new Identity Provider configuration.

```bash
authtest config idp add NAME [OPTIONS]
```

##### Arguments

| Argument | Description |
|----------|-------------|
| `NAME` | Unique identifier for this IdP (e.g., 'okta-prod', 'keycloak-dev') |

##### Options

| Option | Description |
|--------|-------------|
| `--type [saml\|oidc]` | Identity Provider type |
| `--display-name TEXT` | Display name for the IdP |
| `--entity-id TEXT` | SAML Entity ID |
| `--sso-url TEXT` | SAML SSO URL |
| `--slo-url TEXT` | SAML SLO URL |
| `--metadata-url TEXT` | SAML metadata URL (auto-fetches configuration) |
| `--issuer TEXT` | OIDC Issuer URL |
| `--authorization-endpoint TEXT` | OIDC Authorization endpoint |
| `--token-endpoint TEXT` | OIDC Token endpoint |
| `--userinfo-endpoint TEXT` | OIDC UserInfo endpoint |
| `--jwks-uri TEXT` | OIDC JWKS URI |
| `-i, --interactive/--no-interactive` | Enable/disable interactive prompts |
| `--json` | Output results as JSON |

##### Examples

```bash
# Interactive mode - prompts for all values
authtest config idp add my-okta -i

# Non-interactive SAML configuration
authtest config idp add my-saml --type saml \
    --entity-id https://idp.example.com \
    --sso-url https://idp.example.com/sso \
    --display-name "Production Okta"

# OIDC configuration with discovery
authtest config idp add my-oidc --type oidc \
    --issuer https://accounts.google.com

# JSON output for scripting
authtest config idp add my-idp --type saml --json
```

---

#### authtest config idp edit

Edit an existing Identity Provider configuration.

```bash
authtest config idp edit NAME [OPTIONS]
```

##### Options

| Option | Description |
|--------|-------------|
| `--display-name TEXT` | Display name for the IdP |
| `--enabled/--disabled` | Enable or disable the IdP |
| `--entity-id TEXT` | SAML Entity ID |
| `--sso-url TEXT` | SAML SSO URL |
| `--slo-url TEXT` | SAML SLO URL |
| `--metadata-url TEXT` | SAML metadata URL |
| `--issuer TEXT` | OIDC Issuer URL |
| `--authorization-endpoint TEXT` | OIDC Authorization endpoint |
| `--token-endpoint TEXT` | OIDC Token endpoint |
| `--userinfo-endpoint TEXT` | OIDC UserInfo endpoint |
| `--jwks-uri TEXT` | OIDC JWKS URI |
| `--json` | Output results as JSON |

##### Examples

```bash
# Update display name
authtest config idp edit my-okta --display-name "Okta Production"

# Disable an IdP
authtest config idp edit my-okta --disabled

# Update SAML endpoints
authtest config idp edit my-saml --sso-url https://new-idp.example.com/sso
```

---

#### authtest config idp remove

Remove an Identity Provider configuration.

```bash
authtest config idp remove NAME [OPTIONS]
```

##### Options

| Option | Description |
|--------|-------------|
| `-f, --force` | Skip confirmation prompt |
| `--json` | Output results as JSON |

##### Examples

```bash
# Remove with confirmation prompt
authtest config idp remove my-okta

# Remove without confirmation
authtest config idp remove my-okta --force
```

---

#### authtest config idp list

List all configured Identity Providers.

```bash
authtest config idp list [OPTIONS]
```

##### Options

| Option | Description |
|--------|-------------|
| `--json` | Output results as JSON |

##### Examples

```bash
# List all IdPs
authtest config idp list

# List as JSON
authtest config idp list --json
```

---

#### authtest config idp show

Show detailed configuration for an Identity Provider.

```bash
authtest config idp show NAME [OPTIONS]
```

##### Options

| Option | Description |
|--------|-------------|
| `--json` | Output results as JSON |

##### Examples

```bash
# Show IdP details
authtest config idp show my-okta

# Show as JSON
authtest config idp show my-okta --json
```

---

#### authtest config idp from-preset

Add an Identity Provider from a preset configuration.

```bash
authtest config idp from-preset NAME [OPTIONS]
```

##### Options

| Option | Description |
|--------|-------------|
| `--preset [keycloak]` | IdP preset to use (required) |
| `--type [saml\|oidc]` | Protocol type (default: saml) |
| `--base-url TEXT` | IdP server base URL (required) |
| `--realm TEXT` | Keycloak realm name (required for keycloak preset) |
| `--display-name TEXT` | Display name for the IdP |
| `--discover/--no-discover` | Auto-discover and fetch metadata/config (default: discover) |
| `--json` | Output results as JSON |

##### Examples

```bash
# Add Keycloak SAML IdP
authtest config idp from-preset my-keycloak \
    --preset keycloak \
    --base-url https://keycloak.example.com \
    --realm myrealm

# Add Keycloak OIDC IdP with auto-discovery
authtest config idp from-preset my-keycloak-oidc \
    --preset keycloak \
    --type oidc \
    --base-url https://keycloak.example.com \
    --realm myrealm

# Add without fetching metadata
authtest config idp from-preset my-keycloak \
    --preset keycloak \
    --base-url https://keycloak.example.com \
    --realm myrealm \
    --no-discover
```

---

#### authtest config idp setup-guide

Show setup guide for an IdP preset.

```bash
authtest config idp setup-guide [OPTIONS]
```

##### Options

| Option | Description |
|--------|-------------|
| `--preset [keycloak]` | IdP preset for setup guide (required) |
| `--base-url TEXT` | IdP server base URL (for customized URLs) |
| `--realm TEXT` | Keycloak realm name (for customized URLs) |

##### Examples

```bash
# Show Keycloak setup guide
authtest config idp setup-guide --preset keycloak

# Show guide with customized URLs
authtest config idp setup-guide --preset keycloak \
    --base-url https://keycloak.example.com \
    --realm myrealm
```

---

#### authtest config idp discover

Discover IdP configuration from a URL.

```bash
authtest config idp discover URL [OPTIONS]
```

##### Options

| Option | Description |
|--------|-------------|
| `--type [saml\|oidc\|auto]` | Protocol type to discover (default: auto-detect) |
| `--json` | Output results as JSON |

##### Examples

```bash
# Auto-detect and discover
authtest config idp discover https://idp.example.com

# Discover SAML metadata
authtest config idp discover \
    https://keycloak.example.com/realms/test/protocol/saml/descriptor \
    --type saml

# Discover OIDC configuration
authtest config idp discover \
    https://keycloak.example.com/realms/test \
    --type oidc
```

---

### authtest config export

Export configuration to a JSON file.

```bash
authtest config export OUTPUT [OPTIONS]
```

##### Options

| Option | Description |
|--------|-------------|
| `--include-secrets` | Include client secrets in export (not recommended) |
| `--json` | Output results as JSON |

##### Examples

```bash
# Export configuration
authtest config export backup.json

# Export with secrets (use with caution)
authtest config export backup.json --include-secrets
```

---

### authtest config import

Import configuration from a JSON file.

```bash
authtest config import INPUT_FILE [OPTIONS]
```

##### Options

| Option | Description |
|--------|-------------|
| `--merge/--replace` | Merge with existing or replace all (default: merge) |
| `--dry-run` | Show what would be imported without making changes |
| `--json` | Output results as JSON |

##### Examples

```bash
# Import and merge with existing config
authtest config import backup.json

# Replace all existing configuration
authtest config import backup.json --replace

# Preview what would be imported
authtest config import backup.json --dry-run
```

---

## authtest test

Execute authentication flow tests.

### authtest test saml

Execute a SAML authentication flow test.

```bash
authtest test saml FLOW_TYPE [OPTIONS]
```

##### Arguments

| Argument | Description |
|----------|-------------|
| `FLOW_TYPE` | SAML flow type: `sp-initiated`, `idp-initiated`, or `slo` |

##### Options

| Option | Description |
|--------|-------------|
| `-i, --idp TEXT` | IdP configuration to use (required) |
| `--json` | Output results as JSON |

##### Examples

```bash
# Test SP-Initiated SSO
authtest test saml sp-initiated --idp my-keycloak

# Test IdP-Initiated SSO
authtest test saml idp-initiated --idp my-keycloak

# Test Single Logout
authtest test saml slo --idp my-keycloak
```

---

### authtest test oidc

Execute an OIDC authentication flow test.

```bash
authtest test oidc GRANT_TYPE [OPTIONS]
```

##### Arguments

| Argument | Description |
|----------|-------------|
| `GRANT_TYPE` | OIDC grant type: `authorization-code`, `authorization-code-pkce`, `implicit`, `client-credentials`, or `device-code` |

##### Options

| Option | Description |
|--------|-------------|
| `-i, --idp TEXT` | IdP configuration to use (required) |
| `--json` | Output results as JSON |

##### Examples

```bash
# Test Authorization Code flow
authtest test oidc authorization-code --idp my-keycloak

# Test Authorization Code with PKCE
authtest test oidc authorization-code-pkce --idp my-keycloak

# Test Implicit flow
authtest test oidc implicit --idp my-keycloak

# Test Client Credentials flow
authtest test oidc client-credentials --idp my-keycloak

# Test Device Code flow
authtest test oidc device-code --idp my-keycloak
```

---

## authtest certs

Manage TLS certificates and keys.

### authtest certs generate

Generate a new self-signed certificate.

```bash
authtest certs generate [OPTIONS]
```

##### Options

| Option | Description |
|--------|-------------|
| `--type [tls\|signing]` | Certificate type (tls for server, signing for SAML) |
| `-cn, --common-name TEXT` | Common Name (CN) for the certificate (default: localhost) |
| `-d, --days INTEGER` | Days the certificate is valid (default: 365) |
| `-o, --output PATH` | Output directory for certificate files |
| `-f, --force` | Overwrite existing certificate files |

##### Examples

```bash
# Generate default TLS certificate
authtest certs generate

# Generate with custom common name
authtest certs generate --common-name myserver.local

# Generate to specific directory
authtest certs generate --output /path/to/certs

# Generate SAML signing certificate
authtest certs generate --type signing
```

---

### authtest certs import

Import an existing certificate.

```bash
authtest certs import CERT_PATH [OPTIONS]
```

##### Options

| Option | Description |
|--------|-------------|
| `-k, --key PATH` | Private key path (PEM format) |
| `-p, --password TEXT` | Password for encrypted key or PKCS#12 file |
| `-n, --name TEXT` | Name for the imported certificate (default: imported) |
| `-o, --output PATH` | Output directory for converted files |

##### Examples

```bash
# Import PEM certificate and key
authtest certs import /path/to/cert.pem --key /path/to/key.pem

# Import PKCS#12 file
authtest certs import /path/to/cert.p12 --password mypassword

# Import with custom name
authtest certs import /path/to/cert.pem --key /path/to/key.pem --name production
```

---

### authtest certs list

List all managed certificates.

```bash
authtest certs list [OPTIONS]
```

##### Options

| Option | Description |
|--------|-------------|
| `-d, --dir PATH` | Certificate directory to list |

---

### authtest certs inspect

Inspect a certificate's details.

```bash
authtest certs inspect CERT_PATH
```

Shows detailed information about an X.509 certificate including subject, issuer, validity period, extensions, and fingerprints.

---

### authtest certs status

Show TLS certificate status for the server.

```bash
authtest certs status
```

Displays the current TLS configuration and certificate status.

---

## authtest db

Manage AuthTest database.

### authtest db init

Initialize encrypted database with a new encryption key.

```bash
authtest db init [OPTIONS]
```

##### Options

| Option | Description |
|--------|-------------|
| `--db-path PATH` | Path to database file (default: ~/.authtest/authtest.db) |
| `--key-path PATH` | Path to encryption key file (default: ~/.authtest/db.key) |
| `--force` | Overwrite existing database and key files |

---

### authtest db verify

Verify database connection and encryption.

```bash
authtest db verify [OPTIONS]
```

##### Options

| Option | Description |
|--------|-------------|
| `--db-path PATH` | Path to database file |

---

### authtest db migrate

Apply pending database migrations.

```bash
authtest db migrate [OPTIONS]
```

##### Options

| Option | Description |
|--------|-------------|
| `--db-path PATH` | Path to database file |
| `--target TEXT` | Target migration version (default: latest) |

---

### authtest db rollback

Rollback database migrations.

```bash
authtest db rollback [OPTIONS]
```

##### Options

| Option | Description |
|--------|-------------|
| `--db-path PATH` | Path to database file |
| `--target TEXT` | Target migration version to rollback to |

---

### authtest db status

Show database migration status.

```bash
authtest db status [OPTIONS]
```

##### Options

| Option | Description |
|--------|-------------|
| `--db-path PATH` | Path to database file |

---

### authtest db rotate-key

Rotate database encryption key.

```bash
authtest db rotate-key [OPTIONS]
```

Re-encrypts the database with a new key.

##### Options

| Option | Description |
|--------|-------------|
| `--db-path PATH` | Path to database file (required) |
| `--old-key TEXT` | Current encryption key (prompted if not provided) |
| `--new-key TEXT` | New encryption key (generated if not provided) |
| `--save-key PATH` | Path to save the new key file |

**Warning**: Always backup your database before key rotation.

---

### authtest db generate-key

Generate a new AES-256 encryption key.

```bash
authtest db generate-key
```

Outputs a new random key that can be used for database encryption.

---

## JSON Output Mode

Most commands support `--json` flag for scripting:

```bash
# Get IdP list as JSON
authtest config idp list --json

# Parse with jq
authtest config idp list --json | jq '.idps[].name'

# Use in scripts
if authtest config idp show my-idp --json | jq -e '.enabled' > /dev/null; then
    echo "IdP is enabled"
fi
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
