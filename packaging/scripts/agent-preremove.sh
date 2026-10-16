#!/bin/sh
if [ "$1" = "remove" ] || [ "$1" = "0" ]; then
	if [ -d /run/systemd/system ]; then
		systemctl disable --now duckjump-agent.service >/dev/null 2>&1 || true
	fi
fi
exit 0
