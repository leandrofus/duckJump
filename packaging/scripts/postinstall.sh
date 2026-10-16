#!/bin/sh
# deb: $1=configure [old-version]  ·  rpm: $1=1 (install) | 2 (upgrade)
set -e

getent group duckjump >/dev/null 2>&1 || groupadd -r duckjump
if ! getent passwd duckjump >/dev/null 2>&1; then
	useradd -r -g duckjump -d /var/lib/duckjump -s /usr/sbin/nologin -c "DuckJump service" duckjump
fi
install -d -o duckjump -g duckjump -m 0750 /var/lib/duckjump /var/lib/duckjump/recordings

# Secrets live outside the data directory (a backup of /var/lib/duckjump
# alone does not carry them), readable only by root; the services get them
# through systemd LoadCredential.
install -d -m 0755 /etc/duckjump
umask 077
if [ ! -s /etc/duckjump/master.key ]; then
	/usr/libexec/duckjump/palta-gw keygen > /etc/duckjump/master.key
fi
if [ ! -s /etc/duckjump/paltad.token ]; then
	od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > /etc/duckjump/paltad.token
fi
chown root:root /etc/duckjump/master.key /etc/duckjump/paltad.token
chmod 0400 /etc/duckjump/master.key /etc/duckjump/paltad.token
umask 022

upgrade=
if [ "$1" = "2" ] || { [ "$1" = "configure" ] && [ -n "${2:-}" ]; }; then
	upgrade=1
fi

# First install: a superadmin with a random password.
admin_pw=
if [ -z "$upgrade" ] && [ ! -s /var/lib/duckjump/palta.db ]; then
	admin_pw=$(od -An -tx1 -N12 /dev/urandom | tr -d ' \n')
	if /usr/bin/duckjump user -name admin -password "$admin_pw" -role superadmin >/dev/null; then
		(umask 077 && echo "$admin_pw" > /etc/duckjump/initial-admin-password)
	else
		admin_pw=
		echo "warning: could not create the admin user; create it with: sudo duckjump user -name admin -password '...' -role superadmin" >&2
	fi
fi

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload >/dev/null 2>&1 || true
	if [ -n "$upgrade" ]; then
		# keep the admin's choice: only restart what is running
		systemctl try-restart duckjump-paltad.service duckjump.service >/dev/null 2>&1 || true
	else
		systemctl enable duckjump-paltad.service duckjump.service >/dev/null 2>&1 || true
		systemctl restart duckjump-paltad.service duckjump.service >/dev/null 2>&1 || true
	fi
fi

[ -n "$upgrade" ] && exit 0

host=$(uname -n)
cat <<MSG

DuckJump is installed and running: https://$host:8443
  · User admin, password: ${admin_pw:-(see /etc/duckjump/initial-admin-password)}
    (also in /etc/duckjump/initial-admin-password; change it and enable TOTP in My account)
  · The certificate is self-signed: replace it in /etc/duckjump/duckjump.env
  · Firewall:   sudo firewall-cmd --add-port=8443/tcp --permanent && sudo firewall-cmd --reload
                (Debian/Ubuntu with ufw: sudo ufw allow 8443/tcp)
  · CLI:        sudo duckjump user|secret|conn|grant|site …
  · Logs:       journalctl -u duckjump -u duckjump-paltad -f
  · Back up together: /var/lib/duckjump and /etc/duckjump/master.key (without the key the vault cannot be opened)

MSG
