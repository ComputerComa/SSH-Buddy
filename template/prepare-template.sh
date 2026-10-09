#!/usr/bin/env bash
# Pre-template hygiene check. Prints what is wrong; with --clean it removes only SSH Buddy's own per-machine state.
# It never touches /etc/machine-id, SSH host keys or /root/.ssh: those are listed for you to handle deliberately.
set -uo pipefail
clean=0; [ "${1:-}" = "--clean" ] && clean=1
problems=0
bad() { echo "PROBLEM: $*"; problems=$((problems + 1)); }
ok()  { echo "ok:      $*"; }

state=/var/lib/ssh-buddy-agent
if [ -d "$state" ] && [ -n "$(ls -A "$state" 2>/dev/null)" ]; then
  if [ "$clean" = 1 ]; then
    rm -rf "${state:?}"/* "${state:?}"/.[!.]* 2>/dev/null; ok "removed per-machine agent state in $state"
  else
    bad "$state is not empty (machine credential, nonce, sync state or bootstrap marker): run with --clean"
    ls -la "$state" | sed 's/^/           /'
  fi
else
  ok "$state is empty"
fi

[ -e /etc/ssh/authorized_keys.d/root-managed ] && { bad "/etc/ssh/authorized_keys.d/root-managed exists (clones would start with this machine's list)"; \
  [ "$clean" = 1 ] && rm -f /etc/ssh/authorized_keys.d/root-managed; } || ok "no managed key file baked in"
[ -e /run/ssh-buddy-agent.lock ] && rm -f /run/ssh-buddy-agent.lock

[ -s /etc/ssh-buddy/enroll-token ] && ok "enrollment credential present" || bad "missing /etc/ssh-buddy/enroll-token"
perm="$(stat -c %a /etc/ssh-buddy/enroll-token 2>/dev/null)"; [ "$perm" = 600 ] && ok "enroll-token mode 0600" || bad "enroll-token mode is $perm, expected 600"
[ -r /etc/ssh-buddy/agent.conf ] && ok "agent.conf present" || bad "missing /etc/ssh-buddy/agent.conf"
systemctl is-enabled ssh-buddy-bootstrap.service >/dev/null 2>&1 && ok "bootstrap unit enabled" || bad "ssh-buddy-bootstrap.service is not enabled"
[ -e /usr/local/sbin/ssh-buddy-agent ] && echo "note:    an agent binary is baked in; that is fine, the bootstrap replaces it with the server's current build"

if [ -s /etc/machine-id ]; then echo "TODO:    /etc/machine-id is set: truncate it (':> /etc/machine-id') so clones get unique ids"; problems=$((problems + 1)); else ok "/etc/machine-id is empty"; fi
if ls /etc/ssh/ssh_host_*_key >/dev/null 2>&1; then
  echo "TODO:    SSH host keys exist: remove them ('rm /etc/ssh/ssh_host_*'; the bootstrap runs ssh-keygen -A), or clones share host keys"
  problems=$((problems + 1))
else
  ok "no baked SSH host keys"
fi
[ -s /root/.ssh/authorized_keys ] && echo "note:    /root/.ssh/authorized_keys (your recovery keys) is baked in; the agent never modifies it"

echo; [ "$problems" -eq 0 ] && echo "Template looks clean." || echo "$problems item(s) need attention."
exit $(( problems > 0 ))
