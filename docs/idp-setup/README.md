# Identity Provider Setup Guides

This directory contains setup guides for configuring various Identity Providers to work with AuthTest.

## Available Guides

| Identity Provider | Protocol Support | Guide |
|-------------------|------------------|-------|
| [Keycloak](keycloak.md) | SAML, OIDC | Complete setup guide with Docker quick start |

## Planned Guides

The following IdP guides are planned for future releases:

| Identity Provider | Protocol Support | Status |
|-------------------|------------------|--------|
| Okta | SAML, OIDC | Planned |
| Azure AD / Entra ID | SAML, OIDC | Planned |
| Auth0 | SAML, OIDC | Planned |
| Google Workspace | SAML, OIDC | Planned |
| PingFederate | SAML, OIDC | Planned |
| ADFS | SAML, OIDC | Planned |
| OneLogin | SAML, OIDC | Planned |
| JumpCloud | SAML, OIDC | Planned |

## General Setup Steps

Regardless of the IdP, the general setup process is:

### 1. Configure AuthTest

```bash
# Initialize AuthTest (first time only)
authtest init

# Add the IdP using a preset (if available)
authtest config idp from-preset my-idp \
    --preset <preset-name> \
    --base-url <idp-url> \
    [additional options]

# Or add manually
authtest config idp add my-idp -i
```

### 2. Configure the IdP

Each IdP requires:

**For SAML:**
- Create an SP/Application in the IdP
- Configure the ACS URL (Assertion Consumer Service)
- Configure the Entity ID
- Set up attribute mappings
- Download IdP metadata or certificate

**For OIDC:**
- Create an OAuth2/OIDC application
- Configure redirect URIs
- Note the Client ID and Client Secret
- Configure scopes

### 3. Complete Configuration

```bash
# Update AuthTest with IdP certificates/secrets
authtest config idp edit my-idp [options]

# Verify configuration
authtest config idp show my-idp
```

### 4. Test Authentication

```bash
# Test SAML
authtest test saml sp-initiated --idp my-idp

# Test OIDC
authtest test oidc authorization-code --idp my-idp
```

## Custom IdP Configuration

For IdPs not covered by presets, you can configure manually:

### SAML

```bash
authtest config idp add custom-saml --type saml \
    --entity-id "https://your-idp.com/saml/metadata" \
    --sso-url "https://your-idp.com/saml/sso" \
    --slo-url "https://your-idp.com/saml/slo" \
    --metadata-url "https://your-idp.com/saml/metadata"
```

Or use discovery:
```bash
authtest config idp discover https://your-idp.com/saml/metadata --type saml
```

### OIDC

```bash
authtest config idp add custom-oidc --type oidc \
    --issuer "https://your-idp.com" \
    --authorization-endpoint "https://your-idp.com/oauth2/authorize" \
    --token-endpoint "https://your-idp.com/oauth2/token" \
    --userinfo-endpoint "https://your-idp.com/oauth2/userinfo" \
    --jwks-uri "https://your-idp.com/.well-known/jwks.json"
```

Or use OIDC discovery (recommended):
```bash
authtest config idp discover https://your-idp.com --type oidc
```

## Common Configuration Values

### AuthTest SP Information

When configuring your IdP, you'll need these AuthTest values:

| Setting | Value | Description |
|---------|-------|-------------|
| SP Entity ID | `http://localhost:5000/saml/metadata` | SAML Service Provider identifier |
| ACS URL | `http://localhost:5000/saml/acs` | SAML Assertion Consumer Service |
| SLO URL | `http://localhost:5000/saml/slo` | SAML Single Logout |
| OIDC Redirect URI | `http://localhost:5000/oidc/callback` | OAuth2 callback URL |

**Note**: Replace `localhost:5000` with your actual AuthTest URL if different.

### Required IdP Information

From your IdP, you'll need:

**SAML:**
- IdP Entity ID
- SSO URL (Single Sign-On endpoint)
- SLO URL (Single Logout endpoint, optional)
- X.509 Certificate (for signature validation)

**OIDC:**
- Issuer URL
- Authorization endpoint
- Token endpoint
- UserInfo endpoint (optional)
- JWKS URI
- Client ID and Client Secret

## Troubleshooting

See individual IdP guides for provider-specific troubleshooting. Common issues:

1. **Redirect URI mismatch** - Ensure exact match including protocol and trailing slashes
2. **Certificate issues** - Download fresh certificate from IdP
3. **Clock skew** - Ensure server times are synchronized (NTP)
4. **CORS errors** - Configure IdP to allow AuthTest origin
