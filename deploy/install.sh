#!/bin/sh
# Installs or upgrades the SSH Buddy server in this Debian 13 container. Run as root from the unpacked bundle:
#   ./install.sh     install, or upgrade in place (run it again from a newer bundle)
#
# If a filled-in ssh-buddy.env sits next to this script, it is installed as the config (replacing any existing one).
# Otherwise the example is installed only when no config exists, and nothing starts until it names your host.
# The config (/etc/ssh-buddy) and the data (/var/lib/ssh-buddy) are never removed. Before an existing database is
# migrated by a new version, a copy goes to /var/backups/ssh-buddy.
set -eu

APP_DIR=/opt/ssh-buddy
CONF_DIR=/etc/ssh-buddy
CONF=$CONF_DIR/ssh-buddy.env
DATA_DIR=/var/lib/ssh-buddy
BACKUP_DIR=/var/backups/ssh-buddy
UNIT_DIR=/etc/systemd/system
SVC_USER=ssh-buddy

cd "$(dirname "$0")"
version=$(cat VERSION)

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh: must be run as root" >&2
    exit 1
fi
if [ ! -d /run/systemd/system ]; then
    echo "install.sh: systemd is not running in this container" >&2
    exit 1
fi

# The app is self-contained but needs OpenSSL and the CA store; sqlite3 is for backups.
missing=""
for pkg in ca-certificates libssl3t64 sqlite3; do
    dpkg-query -W -f '${Status}' "$pkg" 2>/dev/null | grep -q 'ok installed' || missing="$missing $pkg"
done
if [ -n "$missing" ]; then
    echo "installing:$missing"
    apt-get update -qq
    # shellcheck disable=SC2086 # one word per package
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends $missing >/dev/null
fi

if ! id "$SVC_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
fi
install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$DATA_DIR" "$DATA_DIR/keys" "$DATA_DIR/agent"

install -d -m 0755 "$CONF_DIR"
if [ -f ssh-buddy.env ]; then
    install -m 0640 -o root -g "$SVC_USER" ssh-buddy.env "$CONF"
elif [ ! -f "$CONF" ]; then
    install -m 0640 -o root -g "$SVC_USER" ssh-buddy.env.example "$CONF"
fi
chown root:"$SVC_USER" "$CONF"
chmod 0640 "$CONF"

# Publish the agent release this server version was built with. Copied under a name the server ignores, then
# renamed, so a half-copied release is never served (the server also re-checks SHA256SUMS).
release_dir=$(sed -n 's/^[[:space:]]*Agent__ReleaseDirectory=//p' "$CONF" | tail -n 1)
if [ -z "$release_dir" ]; then
    release_dir=$DATA_DIR/agent
    echo "warning: Agent__ReleaseDirectory is not set in $CONF; add Agent__ReleaseDirectory=$release_dir or the server will not find the agent" >&2
fi
install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$release_dir"
rm -rf "$release_dir/.$version.new"
cp -R "agent/$version" "$release_dir/.$version.new"
chown -R "$SVC_USER:$SVC_USER" "$release_dir/.$version.new"
rm -rf "${release_dir:?}/$version"
mv "$release_dir/.$version.new" "$release_dir/$version"

install -m 0755 ssh-buddy /usr/local/sbin/ssh-buddy
install -m 0755 backup.sh /usr/local/sbin/ssh-buddy-backup

# The defaults keep data in $APP_DIR/App_Data, which the swap below would throw away.
if [ -d "$APP_DIR/App_Data" ]; then
    echo "install.sh: $APP_DIR/App_Data exists: data is being kept inside the app directory." >&2
    echo "Move it to $DATA_DIR and point ConnectionStrings__Default, DataProtection__KeysDirectory and Agent__ReleaseDirectory there first." >&2
    exit 1
fi

fresh=1
if [ -f "$DATA_DIR/sshbuddy.db" ]; then
    fresh=0
    ssh-buddy-backup "$BACKUP_DIR"
    # sqlite3 ran as root; keep any WAL/SHM files it left readable by the service.
    chown "$SVC_USER:$SVC_USER" "$DATA_DIR"/sshbuddy.db*
    echo "database backed up to $BACKUP_DIR"
fi

rm -rf "$APP_DIR.new"
cp -R app "$APP_DIR.new"
chmod 0755 "$APP_DIR.new/SshBuddy.Web"
systemctl stop ssh-buddy.service 2>/dev/null || true
rm -rf "$APP_DIR.old"
if [ -d "$APP_DIR" ]; then
    mv "$APP_DIR" "$APP_DIR.old"
fi
mv "$APP_DIR.new" "$APP_DIR"
rm -rf "$APP_DIR.old"

install -m 0644 ssh-buddy.service "$UNIT_DIR/"
systemctl daemon-reload
systemctl enable ssh-buddy.service >/dev/null

if grep -q 'keys\.home\.example' "$CONF"; then
    echo "Installed SSH Buddy $version (not started). In $CONF set AllowedHosts, App__PublicBaseUrl and"
    echo "ReverseProxy__KnownProxies__0 (or __KnownNetworks__0) for your host and reverse proxy, then run:"
    echo "  systemctl start ssh-buddy"
    echo "  ssh-buddy admin create --email you@example.com"
    exit 0
fi

# ExecStartPre migrates the database, so a failed migration fails the start.
if ! systemctl start ssh-buddy.service || ! sleep 3 || ! systemctl is-active --quiet ssh-buddy.service; then
    journalctl -u ssh-buddy.service -n 30 --no-pager -o cat >&2
    echo "install.sh: SSH Buddy $version did not start; see journalctl -u ssh-buddy" >&2
    exit 1
fi
echo "SSH Buddy $version is running."
if [ "$fresh" = 1 ]; then
    echo "Create the administrator: ssh-buddy admin create --email you@example.com"
fi
