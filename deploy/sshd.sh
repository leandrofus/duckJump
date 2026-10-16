#!/usr/bin/env bash
# OpenSSH server (with SFTP) for testing file transfer: user duckjump /
# duckjump123 on 127.0.0.1:${SSHD_PORT:-12222}.
#   deploy/sshd.sh start | stop
set -euo pipefail
NAME=duckjump-test-sshd
PORT=${SSHD_PORT:-12222}
ENGINE=${ENGINE:-$(command -v docker || command -v podman)}
case "${1:-start}" in
start)
  "$ENGINE" rm -f $NAME >/dev/null 2>&1 || true
  "$ENGINE" run -d --name $NAME -p 127.0.0.1:$PORT:2222 \
    -e PASSWORD_ACCESS=true -e USER_NAME=duckjump -e USER_PASSWORD=duckjump123 \
    docker.io/linuxserver/openssh-server:latest >/dev/null
  for _ in $(seq 1 60); do
    if (exec 3<>/dev/tcp/127.0.0.1/$PORT && head -c 4 <&3 | grep -q SSH) 2>/dev/null; then echo "sshd ready: 127.0.0.1:$PORT"; exit 0; fi
    sleep 1
  done
  echo "sshd did not start" >&2; "$ENGINE" logs --tail 20 $NAME >&2; exit 1 ;;
stop) "$ENGINE" rm -f $NAME >/dev/null 2>&1 || true ;;
*) echo "usage: $0 start|stop" >&2; exit 2 ;;
esac
