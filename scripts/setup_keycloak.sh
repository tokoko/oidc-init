#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
REALM="${REALM:-test-realm}"
CLIENT_ID="${CLIENT_ID:-test-client}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"

# Get admin token
TOKEN=$(curl -sf "${BASE_URL}/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" \
  -d "username=${ADMIN_USER}" \
  -d "password=${ADMIN_PASS}" | jq -r '.access_token')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
  echo "Failed to authenticate with Keycloak at ${BASE_URL}" >&2
  exit 1
fi

AUTH="Authorization: Bearer ${TOKEN}"

# Create realm (ignore 409 = already exists)
HTTP_CODE=$(curl -so /dev/null -w "%{http_code}" "${BASE_URL}/admin/realms" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"realm\":\"${REALM}\",\"enabled\":true,\"sslRequired\":\"none\"}")

case "$HTTP_CODE" in
  201) echo "Realm '${REALM}' created" ;;
  409) echo "Realm '${REALM}' already exists" ;;
  *)   echo "Failed to create realm (HTTP ${HTTP_CODE})" >&2; exit 1 ;;
esac

sleep 1

# Create client with device flow enabled
HTTP_CODE=$(curl -so /dev/null -w "%{http_code}" "${BASE_URL}/admin/realms/${REALM}/clients" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{
    "clientId": "'"${CLIENT_ID}"'",
    "enabled": true,
    "publicClient": true,
    "standardFlowEnabled": true,
    "directAccessGrantsEnabled": true,
    "attributes": {
      "oauth2.device.authorization.grant.enabled": "true"
    },
    "redirectUris": ["http://localhost:*"],
    "webOrigins": ["+"]
  }')

case "$HTTP_CODE" in
  201) echo "Client '${CLIENT_ID}' created" ;;
  409) echo "Client '${CLIENT_ID}' already exists" ;;
  *)   echo "Failed to create client (HTTP ${HTTP_CODE})" >&2; exit 1 ;;
esac

# Create test user (optional, ignore 409)
HTTP_CODE=$(curl -so /dev/null -w "%{http_code}" "${BASE_URL}/admin/realms/${REALM}/users" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "enabled": true,
    "emailVerified": true,
    "email": "testuser@example.com",
    "credentials": [{"type":"password","value":"testpass","temporary":false}]
  }')

case "$HTTP_CODE" in
  201) echo "User 'testuser' created (password: testpass)" ;;
  409) echo "User 'testuser' already exists" ;;
  *)   echo "Failed to create user (HTTP ${HTTP_CODE})" >&2; exit 1 ;;
esac

echo ""
echo "Ready. Test with:"
echo "  oidc-go init --endpoint localhost:8080 --realm ${REALM} --client-id ${CLIENT_ID} --protocol http --no-verify"
