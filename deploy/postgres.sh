#!/usr/bin/env bash
# PostgreSQL for developing and testing the gateway on it.
#   deploy/postgres.sh start   -> postgres://duckjump:duckjump@127.0.0.1:25432/duckjump?sslmode=disable
#   deploy/postgres.sh stop
#   deploy/postgres.sh url
set -euo pipefail
NAME=duckjump-postgres
PORT=${POSTGRES_PORT:-25432}
IMAGE=${POSTGRES_IMAGE:-docker.io/library/postgres:17-alpine}
ENGINE=${ENGINE:-$(command -v docker || command -v podman)}
URL="postgres://duckjump:duckjump@127.0.0.1:$PORT/duckjump?sslmode=disable"

case "${1:-start}" in
start)
  "$ENGINE" rm -f $NAME >/dev/null 2>&1 || true
  "$ENGINE" run -d --name $NAME -p 127.0.0.1:$PORT:5432 \
    -e POSTGRES_USER=duckjump -e POSTGRES_PASSWORD=duckjump -e POSTGRES_DB=duckjump \
    "$IMAGE" >/dev/null
  for _ in $(seq 1 60); do
    if "$ENGINE" exec $NAME pg_isready -U duckjump -d duckjump -h 127.0.0.1 >/dev/null 2>&1; then echo "postgres ready: $URL"; exit 0; fi
    sleep 1
  done
  echo "postgres did not start" >&2; "$ENGINE" logs --tail 30 $NAME >&2; exit 1 ;;
stop) "$ENGINE" rm -f $NAME >/dev/null 2>&1 || true ;;
url) echo "$URL" ;;
*) echo "usage: $0 start|stop|url" >&2; exit 2 ;;
esac
