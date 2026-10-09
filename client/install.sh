#!/usr/bin/env bash
# Install the SSH Buddy sync client on a Debian 13 machine (or LXC template). Run as root.
# Usage: ./install.sh [https://keys.example.com/api/authorized-keys]
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
src="$(cd "$(dirname "$0")" && pwd)"
url="${1:-}"

if [ -n "$url" ]; then
  case "$url" in https://*) ;; *) echo "URL must start with https://" >&2; exit 1 ;; esac
  install -d -m 0755 /etc/ssh-buddy
  printf 'SSH_BUDDY_URL=%s\n' "$url" > /etc/ssh-buddy/client.env
  chmod 0644 /etc/ssh-buddy/client.env
elif ! grep -q '^SSH_BUDDY_URL=https://' /etc/ssh-buddy/client.env 2>/dev/null; then
  echo "Pass the URL as an argument, or create /etc/ssh-buddy/client.env (see client.env.example)." >&2
  exit 1
fi

install -m 0755 "$src/ssh-buddy-sync" /usr/local/sbin/ssh-buddy-sync
# The unit must not depend on this directory existing at start-up, and sshd reads it directly.
install -d -m 0755 -o root -g root /etc/ssh/authorized_keys.d
install -m 0644 "$src/ssh-buddy-sync.service" "$src/ssh-buddy-sync.timer" /etc/systemd/system/

# sshd drop-in: validate, and roll back if sshd rejects the configuration.
dropin=/etc/ssh/sshd_config.d/10-ssh-buddy.conf
install -d -m 0755 /etc/ssh/sshd_config.d
[ -e "$dropin" ] && cp -p "$dropin" "$dropin.bak"
install -m 0644 "$src/10-ssh-buddy.conf" "$dropin"
if ! sshd -t; then
  echo "sshd rejected the new configuration; rolling back." >&2
  if [ -e "$dropin.bak" ]; then mv -f "$dropin.bak" "$dropin"; else rm -f "$dropin"; fi
  exit 1
fi
rm -f "$dropin.bak"
# First match wins in sshd_config, so confirm nothing earlier overrides the drop-in.
if ! sshd -T -C user=root,host=localhost,addr=127.0.0.1 | grep -qi '^authorizedkeysfile .*/etc/ssh/authorized_keys.d/%u-managed'; then
  echo "WARNING: the effective AuthorizedKeysFile does not include the managed file; another sshd setting overrides $dropin." >&2
fi

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  systemctl enable --now ssh-buddy-sync.timer
  systemctl reload ssh 2>/dev/null || true
  echo "Installed. Run 'systemctl start ssh-buddy-sync.service' for an immediate sync."
else
  systemctl enable ssh-buddy-sync.timer 2>/dev/null || true
  echo "Installed (systemd not running; the timer is enabled for next boot)."
fi
