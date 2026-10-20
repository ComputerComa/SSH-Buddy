#!/usr/bin/env bash
# Installs the first-boot bootstrap into an LXC template (as root), either
#   inside the Debian 13 container you are turning into a template, once:
#     ./install-into-template.sh https://keys.home.example [--interval 5m] [--ca /path/to/ca.crt]
#   or into a root filesystem from outside, e.g. a DAB build on the Proxmox host (see docs/template.md):
#     ./install-into-template.sh --root "$(dab basedir)" https://keys.home.example [--interval 5m] [--ca /path/to/ca.crt]
# The URL may be http:// if you run SSH Buddy without TLS (docs/deployment.md); --ca is then unnecessary.
# The enrollment credential is read from stdin (never from the command line, so it stays out of `ps`/history):
#   printf '%s' 'sbt_...' | ./install-into-template.sh https://keys.home.example
#   ./install-into-template.sh --root "$(dab basedir)" https://keys.home.example < ssh-buddy-enroll-token
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

usage="usage: $0 [--root DIR] https://keys.example [--interval 5m] [--ca file]"
url=""; interval=5m; ca=""; root=""
while [ $# -gt 0 ]; do
  case "$1" in
    --interval) interval="${2:?}"; shift 2 ;;
    --ca) ca="${2:?}"; shift 2 ;;
    --root) root="${2:?}"; shift 2 ;;
    -*) echo "unknown option $1" >&2; exit 2 ;;
    *) [ -z "$url" ] || { echo "$usage" >&2; exit 2; }; url="$1"; shift ;;
  esac
done
[ -n "$url" ] || { echo "$usage" >&2; exit 2; }
case "$url" in https://*|http://*) ;; *) echo "url must start with https:// (or http://)" >&2; exit 2 ;; esac
if [ -n "$root" ]; then
  root="$(cd "$root" && pwd)"
  [ "$root" != / ] || root=""
fi
if [ -n "$root" ] && [ ! -d "$root/etc" ]; then echo "$root does not look like a root filesystem" >&2; exit 2; fi

IFS= read -r token || true
case "$token" in sbt_*) ;; *) echo "pipe the template enrollment credential (sbt_...) on stdin" >&2; exit 2 ;; esac

if [ -n "$root" ]; then
  # From outside, look for the files themselves; the host's PATH says nothing about the target.
  [ -x "$root/usr/bin/curl" ] || { echo "curl is required in $root (dab install curl)" >&2; exit 1; }
  [ -x "$root/usr/sbin/sshd" ] || { echo "openssh-server is required in $root (dab install openssh-server)" >&2; exit 1; }
else
  command -v curl >/dev/null || { echo "curl is required (apt install curl)" >&2; exit 1; }
  command -v sshd >/dev/null || [ -x /usr/sbin/sshd ] || { echo "openssh-server is required (apt install openssh-server)" >&2; exit 1; }
fi

if [ -n "$ca" ]; then
  [ -x "$root/usr/sbin/update-ca-certificates" ] || { echo "ca-certificates is required${root:+ in $root}" >&2; exit 1; }
  install -D -m 0644 "$ca" "$root/usr/local/share/ca-certificates/ssh-buddy-ca.crt"
  if [ -n "$root" ]; then chroot "$root" update-ca-certificates; else update-ca-certificates; fi
fi

install -d -m 0755 "$root/etc/ssh-buddy"
printf 'url=%s\ninterval=%s\n' "${url%/}" "$interval" > "$root/etc/ssh-buddy/agent.conf"
chmod 0644 "$root/etc/ssh-buddy/agent.conf"
( umask 077; printf '%s\n' "$token" > "$root/etc/ssh-buddy/enroll-token" )
chmod 0600 "$root/etc/ssh-buddy/enroll-token"

install -D -m 0755 "$here/ssh-buddy-bootstrap" "$root/usr/local/sbin/ssh-buddy-bootstrap"
install -D -m 0644 "$here/ssh-buddy-bootstrap.service" "$root/etc/systemd/system/ssh-buddy-bootstrap.service"
if [ -n "$root" ]; then
  systemctl --root="$root" enable ssh-buddy-bootstrap.service
  echo "Installed into $root. Every container created from this template enrolls on its first boot."
else
  systemctl enable ssh-buddy-bootstrap.service
  echo "Installed. Now run: $here/prepare-template.sh   (checks the container is clean), then shut down and convert to a template."
fi
