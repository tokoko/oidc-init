# Helper Scripts

## setup_keycloak.py

A helper script to create a Keycloak realm and client with device code authorization flow enabled.

### Prerequisites

- Keycloak running on keycloak:8080 (default in devcontainer)
- Python 3.8+ with `requests` library installed

### Usage

**Basic usage** (creates test-realm and test-client):
```bash
uv run python scripts/setup_keycloak.py
```

**Custom realm and client**:
```bash
uv run python scripts/setup_keycloak.py --realm my-realm --client my-client
```

**Create a confidential client** (with client secret):
```bash
uv run python scripts/setup_keycloak.py --realm my-realm --client my-client --confidential
```

**Create with test user**:
```bash
uv run python scripts/setup_keycloak.py --realm my-realm --client my-client --create-test-user
```

### Options

- `--realm` - Realm name (default: test-realm)
- `--client` - Client ID (default: test-client)
- `--client-name` - Client display name (default: same as client ID)
- `--confidential` - Create confidential client instead of public
- `--base-url` - Keycloak base URL (default: http://keycloak:8080)
- `--admin-user` - Admin username (default: admin)
- `--admin-password` - Admin password (default: admin)
- `--create-test-user` - Create a test user (username: testuser, password: testpass)

### What the script does

1. Authenticates with Keycloak admin API
2. Creates a new realm (if it doesn't exist)
3. Creates a new client with:
   - Device authorization grant flow enabled
   - Standard authorization code flow enabled
   - Direct access grants enabled
   - Appropriate redirect URIs configured
4. Optionally creates a test user
5. Displays OIDC endpoint URLs for testing

### Example Output

```
Authenticating with Keycloak at http://keycloak:8080...
Authentication successful!
Creating realm 'my-realm'...
Realm 'my-realm' created successfully!
Creating client 'my-client' in realm 'my-realm'...
  - Public client: True
  - Device authorization grant: enabled
Client 'my-client' created successfully!

======================================================================
Keycloak Setup Complete!
======================================================================

Realm: my-realm
  URL: http://keycloak:8080/realms/my-realm
  Admin Console: http://keycloak:8080/admin/my-realm/console/

Client: my-client
  Type: Public
  Device Flow: Enabled

OIDC Endpoints:
  Token: http://keycloak:8080/realms/my-realm/protocol/openid-connect/token
  Device Auth: http://keycloak:8080/realms/my-realm/protocol/openid-connect/auth/device
  Well-known: http://keycloak:8080/realms/my-realm/.well-known/openid-configuration
======================================================================
```

### Testing the Setup

After running the script, you can test the device flow:

1. **Get device code**:
   ```bash
   curl -X POST http://keycloak:8080/realms/my-realm/protocol/openid-connect/auth/device \
     -d "client_id=my-client"
   ```

2. **Verify the device**:
   - Open the verification URI in a browser
   - Enter the user code
   - Login with test user (if created): testuser / testpass

3. **Exchange device code for tokens**:
   ```bash
   curl -X POST http://keycloak:8080/realms/my-realm/protocol/openid-connect/token \
     -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
     -d "client_id=my-client" \
     -d "device_code=<device_code_from_step_1>"
   ```
