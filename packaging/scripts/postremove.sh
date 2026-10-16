#!/bin/sh
# Data (/var/lib/duckjump), keys (/etc/duckjump) and the duckjump user are
# kept on remove; deb purge deletes them.
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload >/dev/null 2>&1 || true
fi
if [ "$1" = "purge" ]; then
	rm -rf /var/lib/duckjump /etc/duckjump
	userdel duckjump >/dev/null 2>&1 || true
	groupdel duckjump >/dev/null 2>&1 || true
fi
exit 0
