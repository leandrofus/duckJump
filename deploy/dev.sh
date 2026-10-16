#!/usr/bin/env bash
# Levanta el entorno de desarrollo: sshd de prueba (podman), duckjumpd y duckjump-gw.
# Uso: deploy/dev.sh          -> http://127.0.0.1:8088 (admin / duckjump-admin-123)
#      DEV=1 deploy/dev.sh    -> gateway con -dev (sin autenticación)
#      SSO=1 deploy/dev.sh    -> además Keycloak (deploy/keycloak.sh) para el login SSO
#      PG=1 deploy/dev.sh     -> base PostgreSQL (deploy/postgres.sh) en vez de SQLite
#      S3=1 deploy/dev.sh     -> grabaciones terminadas en MinIO (deploy/minio.sh)
#      LISTEN=127.0.0.1:8089 deploy/dev.sh -> otra dirección para el gateway
#      deploy/dev.sh stop
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
RUN=$ROOT/.dev
LISTEN=${LISTEN:-127.0.0.1:8088}
GW=$ROOT/gateway/bin/duckjump-gw

stop() {
  [[ -f $RUN/pids ]] && kill $(cat "$RUN/pids") 2>/dev/null || true
  rm -f "$RUN/pids"
  podman rm -f duckjump-sshd duckjump-vnc duckjump-rdp >/dev/null 2>&1 || true
  "$ROOT/deploy/edge.sh" stop >/dev/null 2>&1 || true
  "$ROOT/deploy/keycloak.sh" stop >/dev/null 2>&1 || true
}
if [[ ${1:-} == stop ]]; then stop; echo stopped; exit 0; fi
stop
mkdir -p "$RUN/rec"

# Release por defecto: en debug la codificación PNG/JPEG de las sesiones
# gráficas es varias veces más lenta. DEBUG=1 compila sin optimizar.
PROFILE=release; CARGO_FLAGS=--release
[[ -n ${DEBUG:-} ]] && PROFILE=debug CARGO_FLAGS=
(cd "$ROOT/duckjumpd" && cargo build -q $CARGO_FLAGS)
(cd "$ROOT/duckjumpd/rdp" && cargo build -q $CARGO_FLAGS)   # worker RDP (workspace propio)
D=$ROOT/duckjumpd/target/$PROFILE/duckjumpd
export DUCKJUMPD_RDP_WORKER=$ROOT/duckjumpd/rdp/target/$PROFILE/duckjumpd-rdp
# La UI se embebe en duckjump-gw; sin compilar, el gateway sirve el visor PoC.
if command -v bun >/dev/null && [[ ! -f $ROOT/gateway/internal/server/ui/dist/index.html || -n ${WEB:-} ]]; then
  (cd "$ROOT/gateway" && make -s web >/dev/null)
fi
(cd "$ROOT/gateway" && go build -o bin/duckjump-gw ./cmd/duckjump-gw && CGO_ENABLED=0 go build -o bin/duckjump-agent ./cmd/duckjump-agent)

podman run -d --rm --name duckjump-sshd -p 127.0.0.1:2222:2222 \
  -e PASSWORD_ACCESS=true -e USER_NAME=duckjump -e USER_PASSWORD=duckjump123 \
  docker.io/linuxserver/openssh-server:latest >/dev/null

# Escritorio VNC de prueba (Xvfb + x11vnc + twm + xterm), contraseña vncpass123.
podman run -d --name duckjump-vnc -p 127.0.0.1:5900:5900 docker.io/library/alpine:3.20 sh -c '
  apk add --no-cache xvfb x11vnc xterm twm font-misc-misc xsetroot >/dev/null &&
  (Xvfb :0 -screen 0 1280x800x24 &) && sleep 2 && export DISPLAY=:0 &&
  xsetroot -solid "#2b4a6f" && (twm &) && (xterm -geometry 90x28+40+40 -bg "#101418" -fg "#d8e0e8" &) &&
  exec x11vnc -display :0 -forever -shared -passwd vncpass123 -rfbport 5900 -noxdamage -quiet' >/dev/null

# Servidor RDP de prueba (xrdp + Xorg + twm + xterm), usuario rdpuser / rdppass123.
podman run -d --name duckjump-rdp -p 127.0.0.1:3389:3389 docker.io/library/alpine:3.20 sh -c '
  apk add --no-cache xrdp xorgxrdp xorg-server xterm twm font-misc-misc xsetroot openssl >/dev/null
  id rdpuser >/dev/null 2>&1 || { adduser -D rdpuser && echo "rdpuser:rdppass123" | chpasswd; }
  printf "#!/bin/sh\nxsetroot -solid \"#3d2b6f\" &\nxterm -geometry 90x28+40+40 &\nexec twm\n" > /etc/xrdp/startwm.sh && chmod +x /etc/xrdp/startwm.sh
  [ -f /etc/xrdp/cert.pem ] || openssl req -x509 -newkey rsa:2048 -nodes -keyout /etc/xrdp/key.pem -out /etc/xrdp/cert.pem -days 365 -subj /CN=duckjump-rdp 2>/dev/null
  sed -i "s|^certificate=.*|certificate=/etc/xrdp/cert.pem|; s|^key_file=.*|key_file=/etc/xrdp/key.pem|" /etc/xrdp/xrdp.ini
  xrdp-keygen xrdp auto >/dev/null 2>&1; xrdp-sesman --nodaemon & sleep 1; exec xrdp --nodaemon' >/dev/null

if [[ -n ${SSO:-} ]]; then
  "$ROOT/deploy/keycloak.sh" start
  eval "$("$ROOT/deploy/keycloak.sh" env)"
fi
# Base de antes del renombre (palta -> duckjump).
if [[ -e $RUN/palta.db && ! -e $RUN/duckjump.db ]]; then
  for ext in "" -wal -shm; do [[ -e $RUN/palta.db$ext ]] && mv "$RUN/palta.db$ext" "$RUN/duckjump.db$ext"; done
fi
export DUCKJUMP_DB=$RUN/duckjump.db
if [[ -n ${PG:-} ]]; then
  docker exec duckjump-postgres pg_isready -q >/dev/null 2>&1 || "$ROOT/deploy/postgres.sh" start
  export DUCKJUMP_DB=$("$ROOT/deploy/postgres.sh" url)
fi
if [[ -n ${S3:-} ]]; then
  curl -fs http://127.0.0.1:19000/minio/health/ready >/dev/null 2>&1 || "$ROOT/deploy/minio.sh" start
  eval "$("$ROOT/deploy/minio.sh" env)"
fi
export DUCKJUMPD_TOKEN=dev-token-0123456789abcdef
[[ -f $RUN/master.key ]] || "$GW" keygen > "$RUN/master.key"
export DUCKJUMP_MASTER_KEY=$(cat "$RUN/master.key")

# SQL directo sobre la base de desarrollo, sea SQLite o PostgreSQL.
q() {
  if [[ $DUCKJUMP_DB == postgres://* ]]; then docker exec duckjump-postgres psql -U duckjump -d duckjump -tAc "$1"
  else sqlite3 "$DUCKJUMP_DB" "$1"; fi
}
# Base de la PoC anterior (otro esquema): se recrea.
if [[ $DUCKJUMP_DB != postgres://* && -f $DUCKJUMP_DB ]] && ! sqlite3 "$DUCKJUMP_DB" "SELECT 1 FROM config_users LIMIT 1" >/dev/null 2>&1; then
  echo "base con esquema viejo: recreando"
  rm -f "$DUCKJUMP_DB" "$DUCKJUMP_DB-wal" "$DUCKJUMP_DB-shm" "$RUN/edge.token"
fi
if ! q "SELECT 1 FROM config_users WHERE username = 'admin'" 2>/dev/null | grep -q 1; then
  "$GW" user -name admin -password duckjump-admin-123 -role superadmin
  "$GW" secret -name test-pw -user duckjump -password duckjump123
  "$GW" conn -name sshd-local -host 127.0.0.1 -port 2222 -secret test-pw -record-input
  "$GW" grant -user admin -conn sshd-local -upload -download
fi
if ! q "SELECT 1 FROM config_connections WHERE name = 'rdp-local'" | grep -q 1; then
  "$GW" secret -name rdp-pw -user rdpuser -password rdppass123
  "$GW" conn -name rdp-local -protocol rdp -host 127.0.0.1 -port 3389 -secret rdp-pw
  "$GW" grant -user admin -conn rdp-local
fi
q "UPDATE config_connections SET host_key = NULL WHERE name = 'rdp-local'" >/dev/null 2>&1 || true
if ! q "SELECT 1 FROM config_connections WHERE name = 'vnc-local'" | grep -q 1; then
  "$GW" secret -name vnc-pw -user vnc -password vncpass123
  "$GW" conn -name vnc-local -protocol vnc -host 127.0.0.1 -port 5900 -secret vnc-pw
  "$GW" grant -user admin -conn vnc-local
fi
# El contenedor genera host keys nuevas en cada arranque: despinear.
q "UPDATE config_connections SET host_key = NULL WHERE name = 'sshd-local'" >/dev/null 2>&1 || true
# Bases de antes de las MAC de auditoría: sellar la cadena (idempotente).
"$GW" audit-seal >/dev/null

"$D" --recordings "$RUN/rec" > "$RUN/duckjumpd.log" 2>&1 & echo $! > "$RUN/pids"
# -agent-listen en 0.0.0.0: los contenedores llegan al host por host.containers.internal.
# -trust-on-first-use: los contenedores de prueba cambian de clave en cada arranque;
# en producción las claves nuevas esperan la aprobación de un admin.
"$GW" serve ${DEV:+-dev} -trust-on-first-use -listen "$LISTEN" -agent-listen 0.0.0.0:18443 -recordings "$RUN/rec" -files "$RUN/files" > "$RUN/gw.log" 2>&1 & echo $! >> "$RUN/pids"
sleep 3
echo "listo: http://$LISTEN   usuario admin / duckjump-admin-123   (logs y grabaciones en $RUN)"
