#!/usr/bin/env bash
# Keycloak for developing and testing single sign-on, with the "duckjump"
# realm (deploy/keycloak/duckjump-realm.json): client duckjump / duckjump-test-secret,
# users alice (admin; groups ops, dba), bob (dev), audrey (auditor), all with
# password <name>-password.
#
#   deploy/keycloak.sh start   -> http://127.0.0.1:18180 (console: admin / admin)
#   deploy/keycloak.sh stop
#   deploy/keycloak.sh env     -> duckjump-gw serve environment for the dev stack
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
NAME=duckjump-keycloak
PORT=${KEYCLOAK_PORT:-18180}
IMAGE=${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.4}
ENGINE=${ENGINE:-$(command -v docker || command -v podman)}
URL=http://127.0.0.1:$PORT/realms/duckjump

case "${1:-start}" in
start)
  "$ENGINE" rm -f $NAME >/dev/null 2>&1 || true
  "$ENGINE" run -d --name $NAME -p 127.0.0.1:$PORT:8080 \
    -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
    -e KC_HOSTNAME=http://127.0.0.1:$PORT \
    -v "$ROOT/deploy/keycloak/duckjump-realm.json:/opt/keycloak/data/import/duckjump-realm.json:ro,Z" \
    "$IMAGE" start-dev --import-realm >/dev/null
  for _ in $(seq 1 120); do
    if curl -fs "$URL/.well-known/openid-configuration" >/dev/null 2>&1; then echo "keycloak ready: $URL"; exit 0; fi
    sleep 1
  done
  echo "keycloak did not start; logs:" >&2; "$ENGINE" logs --tail 40 $NAME >&2; exit 1 ;;
stop)
  "$ENGINE" rm -f $NAME >/dev/null 2>&1 || true ;;
env)
  cat <<ENV
export DUCKJUMP_OIDC_ISSUER=$URL
export DUCKJUMP_OIDC_CLIENT_ID=duckjump
export DUCKJUMP_OIDC_CLIENT_SECRET=duckjump-test-secret
export DUCKJUMP_OIDC_REDIRECT_URL=http://127.0.0.1:8088/api/v1/auth/oidc/callback
export DUCKJUMP_OIDC_NAME=Keycloak
export DUCKJUMP_OIDC_ROLES_CLAIM=realm_access.roles
ENV
  ;;
*) echo "usage: $0 start|stop|env" >&2; exit 2 ;;
esac
