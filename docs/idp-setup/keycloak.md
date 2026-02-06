# Keycloak Setup Guide

This guide walks you through setting up a Keycloak realm for testing with AuthTest.

## Prerequisites

- Keycloak server running (see [Quick Start with Docker](#quick-start-with-docker))
- Admin access to the Keycloak console
- AuthTest initialized (`authtest init`)

## Quick Start with Docker

```bash
# Start Keycloak in development mode
docker run -d --name keycloak \
    -p 8080:8080 \
    -e KEYCLOAK_ADMIN=admin \
    -e KEYCLOAK_ADMIN_PASSWORD=admin \
    quay.io/keycloak/keycloak:latest start-dev

# Access admin console at http://localhost:8080/admin
# Login with admin/admin
```

## Adding Keycloak to AuthTest

### Using the Preset (Recommended)

```bash
# Add Keycloak SAML IdP
authtest config idp from-preset my-keycloak \
    --preset keycloak \
    --base-url http://localhost:8080 \
    --realm myrealm

# Add Keycloak OIDC IdP
authtest config idp from-preset my-keycloak-oidc \
    --preset keycloak \
    --type oidc \
    --base-url http://localhost:8080 \
    --realm myrealm
```

### View Setup Instructions

```bash
authtest config idp setup-guide --preset keycloak \
    --base-url http://localhost:8080 \
    --realm myrealm
```

## 1. Create a Realm

1. Log into the Keycloak Admin Console at `http://localhost:8080/admin`
2. Hover over the realm name dropdown (top-left, shows "master")
3. Click **Create Realm**
4. Enter realm name: `authtest` (or your preferred name)
5. Click **Create**

## 2. SAML Client Setup

### Create the Client

1. Go to **Clients** in the left sidebar
2. Click **Create client**
3. Configure:
   - **Client type**: SAML
   - **Client ID**: `http://localhost:5000/saml/metadata` (this is your SP Entity ID)
4. Click **Next**
5. Configure settings:
   - **Name**: AuthTest SAML Client
   - **Description**: SAML SP for AuthTest
   - **Always display in UI**: OFF
6. Click **Next**
7. Configure SAML capabilities:
   - **Name ID format**: email or persistent
   - **Force POST binding**: ON
   - **Include AuthnStatement**: ON
   - **Sign documents**: ON
   - **Sign assertions**: ON
8. Click **Save**

### Configure URLs

1. In the client settings, go to **Settings** tab
2. Configure:
   - **Root URL**: `http://localhost:5000`
   - **Home URL**: `http://localhost:5000`
   - **Valid redirect URIs**: `http://localhost:5000/saml/acs`
   - **IDP-Initiated SSO URL name**: `authtest` (optional, for IdP-initiated flow)
   - **Master SAML Processing URL**: `http://localhost:5000/saml/acs`

3. In **Logout settings**:
   - **Front channel logout**: ON
   - **Logout Service POST Binding URL**: `http://localhost:5000/saml/slo`

### Configure Keys

1. Go to the **Keys** tab
2. Options:
   - **Client signature required**: OFF (simplest, or configure signing in AuthTest)
   - If ON, you'll need to upload AuthTest's SP signing certificate

### Configure Attribute Mappers

1. Go to **Client scopes** tab
2. Click on the dedicated scope (e.g., `authtest-saml-client-dedicated`)
3. Click **Add mapper** > **By configuration**
4. Add these mappers:

| Name | Mapper Type | User Attribute | SAML Attribute Name |
|------|-------------|----------------|---------------------|
| email | User Property | email | email |
| firstName | User Property | firstName | firstName |
| lastName | User Property | lastName | lastName |
| username | User Property | username | username |

For each:
1. Click **User Property**
2. Set Name, Property, and SAML Attribute Name
3. SAML Attribute NameFormat: Basic
4. Click **Save**

## 3. OIDC Client Setup

### Create the Client

1. Go to **Clients** in the left sidebar
2. Click **Create client**
3. Configure:
   - **Client type**: OpenID Connect
   - **Client ID**: `authtest-oidc`
4. Click **Next**
5. Configure:
   - **Client authentication**: ON (confidential client)
   - **Authorization**: OFF
   - **Authentication flow**: Check "Standard flow" and "Direct access grants"
6. Click **Next**
7. Configure login settings:
   - **Root URL**: `http://localhost:5000`
   - **Home URL**: `http://localhost:5000`
   - **Valid redirect URIs**: `http://localhost:5000/oidc/callback`
   - **Valid post logout redirect URIs**: `http://localhost:5000`
   - **Web origins**: `http://localhost:5000`
8. Click **Save**

### Get Client Secret

1. Go to the **Credentials** tab
2. Copy the **Client secret**
3. Save this for configuring AuthTest

### Configure Scopes (Optional)

Default scopes are usually sufficient:
- `openid` - Required for OIDC
- `profile` - Name, username, etc.
- `email` - Email address

To add custom scopes:
1. Go to **Client scopes** in the left sidebar
2. Create or modify scopes as needed
3. Assign to your client

## 4. Create Test Users

1. Go to **Users** in the left sidebar
2. Click **Add user**
3. Fill in:
   - **Username**: testuser
   - **Email**: testuser@example.com
   - **First name**: Test
   - **Last name**: User
   - **Email verified**: ON
4. Click **Create**
5. Go to **Credentials** tab
6. Click **Set password**
7. Enter password and confirm
8. Set **Temporary**: OFF
9. Click **Save**

## 5. Configure AuthTest

### For SAML

```bash
# If using preset with auto-discovery
authtest config idp from-preset keycloak-saml \
    --preset keycloak \
    --type saml \
    --base-url http://localhost:8080 \
    --realm authtest

# Verify configuration
authtest config idp show keycloak-saml
```

### For OIDC

```bash
# Add the IdP
authtest config idp from-preset keycloak-oidc \
    --preset keycloak \
    --type oidc \
    --base-url http://localhost:8080 \
    --realm authtest

# Configure client credentials (interactive)
authtest config idp edit keycloak-oidc
# Add client_id and client_secret when prompted
```

## 6. Test Authentication

### SAML Tests

```bash
# Test SP-Initiated SSO
authtest test saml sp-initiated --idp keycloak-saml

# Test IdP-Initiated SSO (requires IdP-initiated URL configured)
authtest test saml idp-initiated --idp keycloak-saml
```

### OIDC Tests

```bash
# Test Authorization Code flow
authtest test oidc authorization-code --idp keycloak-oidc

# Test with PKCE
authtest test oidc authorization-code-pkce --idp keycloak-oidc

# Test Client Credentials
authtest test oidc client-credentials --idp keycloak-oidc
```

## Quick Reference URLs

For Keycloak at `http://localhost:8080` with realm `authtest`:

| Endpoint | URL |
|----------|-----|
| Admin Console | `http://localhost:8080/admin` |
| Realm Settings | `http://localhost:8080/admin/master/console/#/authtest/realm-settings` |
| SAML Metadata | `http://localhost:8080/realms/authtest/protocol/saml/descriptor` |
| SAML SSO | `http://localhost:8080/realms/authtest/protocol/saml` |
| OIDC Discovery | `http://localhost:8080/realms/authtest/.well-known/openid-configuration` |
| OIDC Auth | `http://localhost:8080/realms/authtest/protocol/openid-connect/auth` |
| OIDC Token | `http://localhost:8080/realms/authtest/protocol/openid-connect/token` |
| OIDC UserInfo | `http://localhost:8080/realms/authtest/protocol/openid-connect/userinfo` |
| JWKS | `http://localhost:8080/realms/authtest/protocol/openid-connect/certs` |
| OIDC Logout | `http://localhost:8080/realms/authtest/protocol/openid-connect/logout` |

## Troubleshooting

### "Invalid redirect URI"

**Problem**: Keycloak rejects the redirect during authentication.

**Solutions**:
1. Check the redirect URI in AuthTest matches exactly what's configured in Keycloak
2. Check for trailing slashes - they must match
3. Ensure protocol (http/https) matches
4. Add both `http://localhost:5000/*` for development flexibility

### "Client not found"

**Problem**: Keycloak can't find the client/SP.

**Solutions**:
1. Verify the client ID/Entity ID matches exactly
2. Check that the client is enabled in Keycloak
3. Ensure you're using the correct realm

### "Invalid signature" (SAML)

**Problem**: SAML signature validation fails.

**Solutions**:
1. Download the latest IdP certificate from Keycloak:
   - Go to **Realm Settings** > **Keys**
   - Click the certificate icon next to the active RS256 key
   - Copy the certificate
2. Update AuthTest with the new certificate:
   ```bash
   authtest config idp edit keycloak-saml --x509-cert "$(cat idp-cert.pem)"
   ```
3. Check signing settings match between Keycloak client config and AuthTest

### "Invalid token" (OIDC)

**Problem**: Token validation fails.

**Solutions**:
1. Check the `iss` claim matches the issuer URL configured
2. Verify the `aud` claim includes your client ID
3. Check token hasn't expired
4. Ensure JWKS URI is accessible

### Certificate Download

To manually get the realm's signing certificate:

1. Go to **Realm Settings** > **Keys**
2. Find the active RS256 key (look for the green checkmark)
3. Click the **Certificate** button (paper icon)
4. Copy the certificate content (includes BEGIN/END markers)

Or via API:
```bash
curl -s http://localhost:8080/realms/authtest/protocol/openid-connect/certs | jq
```

### Session Issues

If sessions aren't persisting:
1. Check Keycloak session timeouts in Realm Settings > Sessions
2. Verify cookies are being set properly
3. Check for mixed HTTP/HTTPS issues

## Advanced Configuration

### Enabling PKCE for Confidential Clients

PKCE is typically for public clients, but can be enabled for additional security:

1. Go to your OIDC client settings
2. In **Advanced** tab
3. Set **Proof Key for Code Exchange Code Challenge Method**: S256

### Configuring Client Scopes

To add custom claims to tokens:

1. Go to **Client scopes**
2. Create a new scope or edit existing
3. Add mappers for custom attributes
4. Assign the scope to your client

### Role Mapping

To include roles in tokens:

1. Go to **Clients** > your client > **Client scopes**
2. Add the `roles` scope
3. Roles will appear in the `realm_access` and `resource_access` claims

## Docker Compose Setup

For a complete development environment:

```yaml
# docker-compose.yml
version: '3.8'

services:
  keycloak:
    image: quay.io/keycloak/keycloak:latest
    command: start-dev
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
    ports:
      - "8080:8080"
    volumes:
      - keycloak_data:/opt/keycloak/data

volumes:
  keycloak_data:
```

Start with:
```bash
docker-compose up -d
```

## Importing/Exporting Realm Configuration

### Export Realm

```bash
docker exec keycloak /opt/keycloak/bin/kc.sh export \
    --realm authtest \
    --file /tmp/realm-export.json

docker cp keycloak:/tmp/realm-export.json ./realm-export.json
```

### Import Realm

```bash
docker cp ./realm-export.json keycloak:/tmp/realm-import.json

docker exec keycloak /opt/keycloak/bin/kc.sh import \
    --file /tmp/realm-import.json
```

Or mount at startup:
```yaml
services:
  keycloak:
    volumes:
      - ./realm-export.json:/opt/keycloak/data/import/realm.json
    command: start-dev --import-realm
```
