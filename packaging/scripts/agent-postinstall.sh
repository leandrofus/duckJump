#!/bin/sh
set -e
install -d -m 0750 /etc/duckjump-agent
upgrade=
if [ "$1" = "2" ] || { [ "$1" = "configure" ] && [ -n "${2:-}" ]; }; then
	upgrade=1
fi
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload >/dev/null 2>&1 || true
	if [ -n "$upgrade" ]; then
		systemctl try-restart duckjump-agent.service >/dev/null 2>&1 || true
	else
		# enabled now; it starts once /etc/duckjump-agent/token exists
		systemctl enable duckjump-agent.service >/dev/null 2>&1 || true
		systemctl restart duckjump-agent.service >/dev/null 2>&1 || true
	fi
fi
[ -n "$upgrade" ] && exit 0
cat <<'MSG'

duckjump-agent is installed. To connect it:
  1. In DuckJump: Sites → New site (edge agent), copy the token
  2. sudo sh -c 'umask 077; echo TOKEN > /etc/duckjump-agent/token'
  3. Set PALTA_AGENT_SERVER and PALTA_AGENT_ALLOW in /etc/duckjump-agent/agent.env
  4. sudo systemctl restart duckjump-agent   (logs: journalctl -u duckjump-agent -f)

MSG
