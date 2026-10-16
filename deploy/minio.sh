#!/usr/bin/env bash
# S3-compatible object storage (MinIO) for developing and testing recording
# storage in S3. Bucket "duckjump-recordings", keys duckjump / duckjump-secret-key.
#   deploy/minio.sh start   -> http://127.0.0.1:19000 (console :19001)
#   deploy/minio.sh stop
#   deploy/minio.sh env     -> DUCKJUMP_S3_* for duckjumpd and duckjump-gw
# MinIO no longer publishes images (minio/minio is gone from Docker Hub and
# quay.io); Chainguard's build is free for :latest. MINIO_IMAGE overrides it:
# any MinIO image with a shell works. It runs as non-root, hence /tmp/data.
set -euo pipefail
NAME=duckjump-minio
PORT=${MINIO_PORT:-19000}
IMAGE=${MINIO_IMAGE:-cgr.dev/chainguard/minio:latest}
ENGINE=${ENGINE:-$(command -v docker || command -v podman)}
BUCKET=duckjump-recordings

env_vars() {
  cat <<ENV
export DUCKJUMP_S3_ENDPOINT=http://127.0.0.1:$PORT
export DUCKJUMP_S3_BUCKET=$BUCKET
export DUCKJUMP_S3_REGION=us-east-1
export DUCKJUMP_S3_ACCESS_KEY=duckjump
export DUCKJUMP_S3_SECRET_KEY=duckjump-secret-key
export DUCKJUMP_S3_PATH_STYLE=1
ENV
}

case "${1:-start}" in
start)
  "$ENGINE" rm -f $NAME >/dev/null 2>&1 || true
  "$ENGINE" run -d --name $NAME -p 127.0.0.1:$PORT:9000 -p 127.0.0.1:$((PORT + 1)):9001 \
    -e MINIO_ROOT_USER=duckjump -e MINIO_ROOT_PASSWORD=duckjump-secret-key \
    --entrypoint sh "$IMAGE" -c "mkdir -p /tmp/data/$BUCKET && exec minio server /tmp/data --console-address :9001" >/dev/null
  for _ in $(seq 1 60); do
    if curl -fs "http://127.0.0.1:$PORT/minio/health/ready" >/dev/null 2>&1; then echo "minio ready: http://127.0.0.1:$PORT bucket $BUCKET"; exit 0; fi
    sleep 1
  done
  echo "minio did not start" >&2; "$ENGINE" logs --tail 30 $NAME >&2; exit 1 ;;
stop) "$ENGINE" rm -f $NAME >/dev/null 2>&1 || true ;;
env) env_vars ;;
*) echo "usage: $0 start|stop|env" >&2; exit 2 ;;
esac
