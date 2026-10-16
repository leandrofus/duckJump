#!/usr/bin/env bash
# Levanta el entorno de desarrollo: sshd de prueba (podman), paltad y palta-gw.
# Uso: deploy/dev.sh          -> http://127.0.0.1:8088 (admin / palta-admin-123)
#      DEV=1 deploy/dev.sh    -> gateway con -dev (sin autenticación)
#      deploy/dev.sh stop
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
RUN=$ROOT/.dev
GW=$ROOT/gateway/bin/palta-gw

stop() {
  [[ -f $RUN/pids ]] && kill $(cat "$RUN/pids") 2>/dev/null || true
  rm -f "$RUN/pids"
  podman rm -f palta-sshd palta-vnc palta-rdp >/dev/null 2>&1 || true
  "$ROOT/deploy/edge.sh" stop >/dev/null 2>&1 || true
}
if [[ ${1:-} == stop ]]; then stop; echo stopped; exit 0; fi
stop
mkdir -p "$RUN/rec"

# Release por defecto: en debug la codificación PNG/JPEG de las sesiones
# gráficas es varias veces más lenta. DEBUG=1 compila sin optimizar.
PROFILE=release; CARGO_FLAGS=--release
[[ -n ${DEBUG:-} ]] && PROFILE=debug CARGO_FLAGS=
(cd "$ROOT/paltad" && cargo build -q $CARGO_FLAGS)
(cd "$ROOT/paltad/rdp" && cargo build -q $CARGO_FLAGS)   # worker RDP (workspace propio)
D=$ROOT/paltad/target/$PROFILE/paltad
export PALTAD_RDP_WORKER=$ROOT/paltad/rdp/target/$PROFILE/paltad-rdp
# La UI se embebe en palta-gw; sin compilar, el gateway sirve el visor PoC.
if command -v bun >/dev/null && [[ ! -f $ROOT/gateway/internal/server/ui/dist/index.html || -n ${WEB:-} ]]; then
  (cd "$ROOT/gateway" && make -s web >/dev/null)
fi
(cd "$ROOT/gateway" && go build -o bin/palta-gw ./cmd/palta-gw && CGO_ENABLED=0 go build -o bin/palta-agent ./cmd/palta-agent)

podman run -d --rm --name palta-sshd -p 127.0.0.1:2222:2222 \
  -e PASSWORD_ACCESS=true -e USER_NAME=palta -e USER_PASSWORD=palta123 \
  docker.io/linuxserver/openssh-server:latest >/dev/null

# Escritorio VNC de prueba (Xvfb + x11vnc + twm + xterm), contraseña vncpass123.
podman run -d --name palta-vnc -p 127.0.0.1:5900:5900 docker.io/library/alpine:3.20 sh -c '
  apk add --no-cache xvfb x11vnc xterm twm font-misc-misc xsetroot >/dev/null &&
  (Xvfb :0 -screen 0 1280x800x24 &) && sleep 2 && export DISPLAY=:0 &&
  xsetroot -solid "#2b4a6f" && (twm &) && (xterm -geometry 90x28+40+40 -bg "#101418" -fg "#d8e0e8" &) &&
  exec x11vnc -display :0 -forever -shared -passwd vncpass123 -rfbport 5900 -noxdamage -quiet' >/dev/null

# Servidor RDP de prueba (xrdp + Xorg + twm + xterm), usuario rdpuser / rdppass123.
podman run -d --name palta-rdp -p 127.0.0.1:3389:3389 docker.io/library/alpine:3.20 sh -c '
  apk add --no-cache xrdp xorgxrdp xorg-server xterm twm font-misc-misc xsetroot openssl >/dev/null
  id rdpuser >/dev/null 2>&1 || { adduser -D rdpuser && echo "rdpuser:rdppass123" | chpasswd; }
  printf "#!/bin/sh\nxsetroot -solid \"#3d2b6f\" &\nxterm -geometry 90x28+40+40 &\nexec twm\n" > /etc/xrdp/startwm.sh && chmod +x /etc/xrdp/startwm.sh
  [ -f /etc/xrdp/cert.pem ] || openssl req -x509 -newkey rsa:2048 -nodes -keyout /etc/xrdp/key.pem -out /etc/xrdp/cert.pem -days 365 -subj /CN=palta-rdp 2>/dev/null
  sed -i "s|^certificate=.*|certificate=/etc/xrdp/cert.pem|; s|^key_file=.*|key_file=/etc/xrdp/key.pem|" /etc/xrdp/xrdp.ini
  xrdp-keygen xrdp auto >/dev/null 2>&1; xrdp-sesman --nodaemon & sleep 1; exec xrdp --nodaemon' >/dev/null

export PALTA_DB=$RUN/palta.db
export PALTAD_TOKEN=dev-token-0123456789abcdef
[[ -f $RUN/master.key ]] || "$GW" keygen > "$RUN/master.key"
export PALTA_MASTER_KEY=$(cat "$RUN/master.key")

# Base de la PoC anterior (otro esquema): se recrea.
if [[ -f $PALTA_DB ]] && ! sqlite3 "$PALTA_DB" "SELECT 1 FROM config_users LIMIT 1" >/dev/null 2>&1; then
  echo "base con esquema viejo: recreando"
  rm -f "$PALTA_DB" "$PALTA_DB-wal" "$PALTA_DB-shm" "$RUN/edge.token"
fi
if [[ ! -f $PALTA_DB ]]; then
  "$GW" user -name admin -password palta-admin-123 -role superadmin
  "$GW" secret -name test-pw -user palta -password palta123
  "$GW" conn -name sshd-local -host 127.0.0.1 -port 2222 -secret test-pw -record-input
  "$GW" grant -user admin -conn sshd-local
fi
if ! sqlite3 "$PALTA_DB" "SELECT 1 FROM config_connections WHERE name = 'rdp-local'" | grep -q 1; then
  "$GW" secret -name rdp-pw -user rdpuser -password rdppass123
  "$GW" conn -name rdp-local -protocol rdp -host 127.0.0.1 -port 3389 -secret rdp-pw
  "$GW" grant -user admin -conn rdp-local
fi
sqlite3 "$PALTA_DB" "UPDATE config_connections SET host_key = NULL WHERE name = 'rdp-local'" 2>/dev/null || true
if ! sqlite3 "$PALTA_DB" "SELECT 1 FROM config_connections WHERE name = 'vnc-local'" | grep -q 1; then
  "$GW" secret -name vnc-pw -user vnc -password vncpass123
  "$GW" conn -name vnc-local -protocol vnc -host 127.0.0.1 -port 5900 -secret vnc-pw
  "$GW" grant -user admin -conn vnc-local
fi
# El contenedor genera host keys nuevas en cada arranque: despinear.
sqlite3 "$PALTA_DB" "UPDATE config_connections SET host_key = NULL WHERE name = 'sshd-local'" 2>/dev/null || true

"$D" --recordings "$RUN/rec" > "$RUN/paltad.log" 2>&1 & echo $! > "$RUN/pids"
# -agent-listen en 0.0.0.0: los contenedores llegan al host por host.containers.internal.
"$GW" serve ${DEV:+-dev} -listen 127.0.0.1:8088 -agent-listen 0.0.0.0:18443 -recordings "$RUN/rec" > "$RUN/gw.log" 2>&1 & echo $! >> "$RUN/pids"
sleep 3
echo "listo: http://127.0.0.1:8088   usuario admin / palta-admin-123   (logs y grabaciones en $RUN)"
