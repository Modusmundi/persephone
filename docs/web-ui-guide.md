# AuthTest Web UI User Guide

This guide covers how to use the AuthTest web interface for testing SAML and OIDC authentication flows.

## Starting the Web Server

```bash
# Start with default settings (HTTPS on port 8443)
authtest serve

# Custom port
authtest serve --port 9443

# With custom TLS certificate
authtest serve --cert /path/to/cert.pem --key /path/to/key.pem
```

Access the web interface at: `https://localhost:8443`

**Note**: The first time you access the server, your browser will show a certificate warning because AuthTest uses a self-signed certificate by default. Accept the certificate to continue.

## First-Time Setup

### 1. Password Setup

If password protection is enabled (default), you'll be prompted to set a password on first access:

1. Enter a strong password
2. Confirm the password
3. Click "Set Password"

This password is required for all future sessions.

### 2. Initial Configuration

After login, you'll be guided to:

1. **Add an Identity Provider** - Configure your first IdP
2. **Generate Certificates** - Create TLS and signing certificates if needed

## Navigation

The web interface uses a sidebar navigation with the following sections:

| Section | Description |
|---------|-------------|
| **Dashboard** | Overview of configured IdPs and recent tests |
| **SAML** | SAML flow testing (SP-Initiated, IdP-Initiated, SLO) |
| **OIDC** | OIDC flow testing (Auth Code, PKCE, Implicit, etc.) |
| **Configuration** | IdP and client configuration management |
| **History** | View past test results and export reports |
| **Certificates** | Manage TLS and signing certificates |
| **Settings** | Application settings and preferences |

## Managing Identity Providers

### Adding an IdP

1. Navigate to **Configuration > Identity Providers**
2. Click **Add IdP**
3. Choose configuration method:

**From Preset:**
- Select a preset (e.g., Keycloak)
- Enter the base URL and required parameters
- Click "Discover" to auto-fetch metadata

**Manual Configuration:**
- Select protocol type (SAML or OIDC)
- Enter the required endpoints manually

### SAML IdP Fields

| Field | Description | Required |
|-------|-------------|----------|
| Name | Unique identifier | Yes |
| Display Name | Friendly name | No |
| Entity ID | IdP's SAML Entity ID | Yes |
| SSO URL | Single Sign-On endpoint | Yes |
| SLO URL | Single Logout endpoint | No |
| Metadata URL | URL to fetch SAML metadata | No |
| X.509 Certificate | IdP signing certificate | Yes |

### OIDC IdP Fields

| Field | Description | Required |
|-------|-------------|----------|
| Name | Unique identifier | Yes |
| Display Name | Friendly name | No |
| Issuer | OIDC Issuer URL | Yes |
| Authorization Endpoint | OAuth2 authorization URL | Yes |
| Token Endpoint | OAuth2 token URL | Yes |
| UserInfo Endpoint | OIDC userinfo URL | No |
| JWKS URI | JSON Web Key Set URL | Yes |

## Testing SAML Flows

### SP-Initiated SSO

Service Provider-initiated Single Sign-On:

1. Navigate to **SAML > SP-Initiated SSO**
2. Select an IdP from the dropdown
3. Review the pre-flight checklist:
   - SP Entity ID
   - ACS URL
   - IdP SSO URL
   - Certificates status
4. Click **Start Test**
5. Authenticate at your IdP
6. View the results:
   - SAML Response (XML)
   - Decoded Assertion
   - Attributes/Claims
   - Signature Validation

### IdP-Initiated SSO

Identity Provider-initiated Single Sign-On:

1. Navigate to **SAML > IdP-Initiated SSO**
2. Select an IdP
3. Copy the SP metadata URL or ACS URL to configure in your IdP
4. Initiate login from your IdP
5. AuthTest receives and decodes the assertion

### Single Logout (SLO)

Test SAML logout flows:

1. Navigate to **SAML > Single Logout**
2. Ensure you have an active session
3. Select logout type:
   - **SP-Initiated**: Logout starts from AuthTest
   - **IdP-Initiated**: Logout starts from IdP
4. Click **Initiate Logout**
5. View the logout request/response

## Testing OIDC Flows

### Authorization Code Flow

Standard OAuth2 authorization code flow:

1. Navigate to **OIDC > Authorization Code**
2. Select an IdP
3. Configure options:
   - Scopes (openid, profile, email, etc.)
   - State parameter
   - Nonce parameter
4. Click **Start Flow**
5. Authenticate at your IdP
6. View the results:
   - Authorization Code
   - Token Response (access_token, id_token, refresh_token)
   - Decoded ID Token
   - UserInfo response

### Authorization Code with PKCE

Secure flow for public clients:

1. Navigate to **OIDC > Authorization Code + PKCE**
2. Select an IdP
3. PKCE parameters are auto-generated:
   - Code Verifier
   - Code Challenge (S256)
4. Click **Start Flow**
5. Complete authentication
6. View results with PKCE verification status

### Implicit Flow

Legacy flow (testing purposes only):

1. Navigate to **OIDC > Implicit**
2. Select an IdP
3. Choose response type:
   - `token` - Access token only
   - `id_token` - ID token only
   - `id_token token` - Both tokens
4. Click **Start Flow**
5. View tokens returned in URL fragment

### Client Credentials Flow

Machine-to-machine authentication:

1. Navigate to **OIDC > Client Credentials**
2. Select an IdP with client credentials configured
3. Configure options:
   - Scopes
   - Additional parameters
4. Click **Execute**
5. View the access token response

### Device Code Flow

For devices with limited input:

1. Navigate to **OIDC > Device Code**
2. Select an IdP
3. Click **Request Code**
4. View:
   - Device code
   - User code
   - Verification URL
5. Complete authentication on another device
6. AuthTest polls for the token

## Viewing Results

### Result Viewer

Each test result includes:

1. **Summary**
   - Status (Success/Failure)
   - Timestamp
   - Duration
   - Flow type

2. **Protocol Data**
   - Raw requests/responses
   - HTTP headers
   - Redirects traced

3. **Token/Assertion**
   - Decoded view with syntax highlighting
   - Claim-by-claim breakdown
   - Signature validation status

4. **Timeline**
   - Step-by-step flow visualization
   - Timing for each step

### Inspecting Tokens

**SAML Assertions:**
- XML structure with collapsible nodes
- Attribute statements
- Conditions (NotBefore, NotOnOrAfter, AudienceRestriction)
- Signature verification

**JWT Tokens:**
- Header, Payload, Signature sections
- Decoded JSON with formatting
- Standard claims (iss, sub, aud, exp, iat)
- Custom claims highlighted

## Test History

### Viewing History

1. Navigate to **History**
2. Filter by:
   - IdP
   - Flow type (SAML/OIDC)
   - Date range
   - Status (Success/Failure)
3. Click on a result to view details

### Comparing Results

1. Select two or more test results
2. Click **Compare**
3. View side-by-side diff of:
   - Claims/attributes
   - Token contents
   - Timing differences

### Exporting Reports

1. Select test result(s)
2. Click **Export**
3. Choose format:
   - **JSON** - Full technical detail for scripting
   - **PDF** - Formatted report for documentation
   - **HTML** - Standalone shareable report
4. Download the report

## Certificate Management

### Viewing Certificates

1. Navigate to **Certificates**
2. View all certificates:
   - TLS server certificate
   - SAML signing certificate
   - IdP certificates

### Certificate Details

Click on a certificate to view:
- Subject/Issuer
- Validity period
- Key type and size
- Fingerprints (SHA-256)
- Subject Alternative Names

### Generating Certificates

1. Click **Generate Certificate**
2. Select type:
   - **TLS** - For HTTPS server
   - **Signing** - For SAML SP signing
3. Configure:
   - Common Name
   - Validity (days)
4. Click **Generate**

## Settings

### Security Settings

- **Password Protection**: Enable/disable and change password
- **Session Timeout**: Auto-logout after inactivity
- **API Access**: Enable/disable JSON API

### Display Settings

- **Theme**: Light/Dark mode
- **Syntax Highlighting**: Choose color scheme
- **Time Format**: Local/UTC timestamps

### Protocol Settings

- **SAML Defaults**: Signature requirements, NameID format
- **OIDC Defaults**: Default scopes, PKCE settings

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+/` | Show keyboard shortcuts |
| `Ctrl+Enter` | Execute current test |
| `Escape` | Close modal/dialog |
| `?` | Toggle help panel |

## Troubleshooting

### Certificate Warnings

The self-signed certificate will trigger browser warnings. To avoid this:

1. Generate a proper certificate:
   ```bash
   authtest certs generate --common-name your-domain.local
   ```

2. Add the CA to your browser's trust store

### CORS Issues

If testing against an IdP with CORS restrictions:

1. Ensure AuthTest's origin is allowed in the IdP
2. Use the popup flow instead of redirect if available

### Session Problems

If your session keeps expiring:

1. Check session timeout in Settings
2. Ensure cookies are enabled
3. Check browser's third-party cookie settings

### Connection Refused

If you can't connect to the web interface:

1. Check the server is running: `authtest serve`
2. Verify the port isn't blocked
3. Check firewall settings
4. Try accessing via IP: `https://127.0.0.1:8443`

## API Access

The web interface also exposes a JSON API for automation:

```bash
# Get IdP list
curl -k https://localhost:8443/api/idp

# Execute test (requires session)
curl -k -X POST https://localhost:8443/api/test/saml/sp-initiated \
    -H "Content-Type: application/json" \
    -d '{"idp": "my-keycloak"}'
```

See the API documentation at `https://localhost:8443/api/docs` when the server is running.
