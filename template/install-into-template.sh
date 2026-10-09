#!/usr/bin/env bash
# Run ONCE inside the Debian 13 container you are turning into a template (as root).
#   ./install-into-template.sh https://keys.home.example [--interval 5m] [--ca /path/to/ca.crt]
# The enrollment credential is read from stdin (never from the command line, so it stays out of `ps`/history):
#   printf '%s' 'sbt_...' | ./install-into-template.sh https://keys.home.example
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

url="${1:?usage: $0 https://keys.example [--interval 5m] [--ca file]}"; shift
interval=5m; ca=""
while [ $# -gt 0 ]; do
  case "$1" in
    --interval) interval="${2:?}"; shift 2 ;;
    --ca) ca="${2:?}"; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
case "$url" in https://*) ;; *) echo "url must start with https://" >&2; exit 2 ;; esac

IFS= read -r token || true
case "$token" in sbt_*) ;; *) echo "pipe the template enrollment credential (sbt_...) on stdin" >&2; exit 2 ;; esac

command -v curl >/dev/null || { echo "curl is required (apt install curl)" >&2; exit 1; }
command -v sshd >/dev/null || [ -x /usr/sbin/sshd ] || { echo "openssh-server is required (apt install openssh-server)" >&2; exit 1; }

if [ -n "$ca" ]; then
  install -m 0644 "$ca" /usr/local/share/ca-certificates/ssh-buddy-ca.crt
  update-ca-certificates
fi

install -d -m 0755 /etc/ssh-buddy
printf 'url=%s\ninterval=%s\n' "${url%/}" "$interval" > /etc/ssh-buddy/agent.conf
chmod 0644 /etc/ssh-buddy/agent.conf
( umask 077; printf '%s\n' "$token" > /etc/ssh-buddy/enroll-token )
chmod 0600 /etc/ssh-buddy/enroll-token

install -m 0755 "$here/ssh-buddy-bootstrap" /usr/local/sbin/ssh-buddy-bootstrap
install -m 0644 "$here/ssh-buddy-bootstrap.service" /etc/systemd/system/ssh-buddy-bootstrap.service
systemctl enable ssh-buddy-bootstrap.service

echo "Installed. Now run: $here/prepare-template.sh   (checks the container is clean), then shut down and convert to a template."
