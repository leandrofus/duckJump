#!/bin/sh
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload >/dev/null 2>&1 || true
fi
if [ "$1" = "purge" ]; then
	rm -rf /etc/duckjump-agent
fi
exit 0
