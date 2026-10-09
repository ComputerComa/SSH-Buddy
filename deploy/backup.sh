#!/usr/bin/env bash
# Consistent online backup of the SQLite database (safe while the app is running).
# Usage: backup.sh /var/backups/ssh-buddy
set -euo pipefail
dest="${1:?destination directory}"
install -d -m 0700 "$dest"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
sqlite3 /var/lib/ssh-buddy/sshbuddy.db "VACUUM INTO '$dest/sshbuddy-$stamp.db'"
# Data-protection keys keep the admin session cookies valid across restores (optional but small).
tar -C /var/lib/ssh-buddy -czf "$dest/keys-$stamp.tar.gz" keys
chmod 0600 "$dest"/*"$stamp"*
find "$dest" -name 'sshbuddy-*.db' -mtime +30 -delete
find "$dest" -name 'keys-*.tar.gz' -mtime +30 -delete
