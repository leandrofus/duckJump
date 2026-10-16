#!/usr/bin/env bash
# Simula un sitio edge: una red cerrada (--internal, sin salida ni entrada) con
# un sshd que solo el agente puede alcanzar. El agente sale a internet por una
# segunda red y abre el túnel inverso hacia palta-gw.
#
#   deploy/dev.sh && deploy/edge.sh     -> conexión "edge-sshd" en la UI
#   deploy/edge.sh stop
#
#   palta-wan (con salida)        palta-edge-lan (10.89.50.0/24, --internal)
#   palta-agent ──────────────────┼── palta-agent (10.89.50.2)
#      │ WSS saliente             └── edge-sshd   (10.89.50.10:2222)
#      ▼
#   host: palta-gw -agent-listen 0.0.0.0:18443
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
RUN=$ROOT/.dev
GW=$ROOT/gateway/bin/palta-gw
SITE=edge1

if [[ ${1:-} == stop ]]; then
  podman rm -f palta-edge-agent palta-edge-sshd >/dev/null 2>&1 || true
  podman network rm -f palta-edge-lan palta-wan >/dev/null 2>&1 || true
  echo "edge stopped"; exit 0
fi

[[ -f $RUN/master.key ]] || { echo "primero corré deploy/dev.sh"; exit 1; }
export PALTA_DB=$RUN/palta.db PALTA_MASTER_KEY=$(cat "$RUN/master.key")

podman network exists palta-wan || podman network create palta-wan >/dev/null
podman network exists palta-edge-lan || podman network create --internal --subnet 10.89.50.0/24 palta-edge-lan >/dev/null

podman rm -f palta-edge-sshd palta-edge-agent >/dev/null 2>&1 || true
podman run -d --name palta-edge-sshd --network palta-edge-lan:ip=10.89.50.10 --hostname edge-sshd \
  -e PASSWORD_ACCESS=true -e USER_NAME=edgeuser -e USER_PASSWORD=edge123 \
  docker.io/linuxserver/openssh-server:latest >/dev/null

# Sitio, credencial y conexión (una sola vez; el token solo se muestra al crear el sitio).
if [[ ! -f $RUN/edge.token ]]; then
  "$GW" site -name "$SITE" | tail -1 > "$RUN/edge.token"
  "$GW" secret -name edge-pw -user edgeuser -password edge123
  "$GW" conn -name edge-sshd -host 10.89.50.10 -port 2222 -secret edge-pw -site "$SITE" -record-input
  "$GW" grant -user admin -conn edge-sshd
fi
sqlite3 "$PALTA_DB" "UPDATE config_connections SET host_key = NULL WHERE name = 'edge-sshd'" 2>/dev/null || true

podman run -d --name palta-edge-agent --hostname edge1-agent \
  --network palta-wan --network palta-edge-lan:ip=10.89.50.2 \
  -v "$ROOT/gateway/bin/palta-agent:/usr/local/bin/palta-agent:ro,z" \
  -e PALTA_AGENT_TOKEN="$(cat "$RUN/edge.token")" \
  docker.io/library/alpine:3.20 \
  palta-agent -server ws://host.containers.internal:18443/agent/connect -allow 10.89.50.0/24:22,2222,3389,5900 >/dev/null

sleep 3
podman logs palta-edge-agent 2>&1 | tail -3
echo "edge listo: en http://127.0.0.1:8088 elegí edge-sshd (edge1)"
