#!/usr/bin/env bash
# End-to-end integration run. Needs: docker (with cgroup v2 + privileged containers), dotnet SDK, go, openssl.
#
#   integration/run.sh            run everything, print a summary, clean up
#   KEEP=1 integration/run.sh     leave containers/network/volume in place for poking around
#
# What it builds and does (about 8-10 minutes, mostly waiting for systemd timers):
#   nginx (TLS from a throwaway CA) -> the published app (Production) <- Debian 13 containers with systemd as PID 1
#   1. real browser (Playwright/Chromium): login, keys, template credential
#   2. build an LXC-template stand-in from that credential, boot a clone: first-boot bootstrap, enrollment, timer
#   3. real ssh login with a key added in the UI; revoke; server outage; stale -> healthy
#   4. the container is "rebuilt": refused, shown as re-enrollment requested, permitted in the UI, enrolls
#   5. secrets grep over every log/database
# Docker stands in for Proxmox LXC; see README "Verification status" for what that does not cover.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
NET=sbnet; VOL=sb-data
PASS=0; FAIL=0
PW_IMAGE=mcr.microsoft.com/playwright:v1.64.0-noble
log()  { printf '\n##### %s\n' "$*"; }
ok()   { printf 'PASS  %s\n' "$*"; PASS=$((PASS + 1)); }
bad()  { printf 'FAIL  %s\n' "$*"; FAIL=$((FAIL + 1)); }
check() { local desc="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi; }

cleanup() {
  [ "${KEEP:-0}" = 1 ] && { echo "KEEP=1: leaving containers (sb-*), network $NET and volume $VOL in place; work dir $WORK"; return; }
  docker rm -f sb-app sb-nginx sb-builder sb-client sb-client2 >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
  docker volume rm "$VOL" >/dev/null 2>&1
  docker rmi -f sb-template >/dev/null 2>&1
}
trap cleanup EXIT

for tool in docker dotnet go openssl; do command -v "$tool" >/dev/null || { echo "missing prerequisite: $tool" >&2; exit 2; }; done
cleanup_first() { docker rm -f sb-app sb-nginx sb-builder sb-client sb-client2 >/dev/null 2>&1; docker network rm "$NET" >/dev/null 2>&1; docker volume rm "$VOL" >/dev/null 2>&1; docker rmi -f sb-template >/dev/null 2>&1; }
cleanup_first

# --------------------------------------------------------------------------- build
log "build: agent release, published app, TLS material, images"
(cd "$ROOT/agent" && ./build.sh >/dev/null) || { echo "agent build failed" >&2; exit 1; }
VERSION="$(tr -d '[:space:]' < "$ROOT/agent/VERSION")"
mkdir -p "$WORK/releases" "$WORK/shared" "$WORK/tls"
cp -r "$ROOT/agent/dist/$VERSION" "$WORK/releases/$VERSION"
dotnet publish "$ROOT/src/SshBuddy.Web" -c Release -r linux-x64 --self-contained -o "$WORK/app" >/dev/null 2>&1 || { echo "publish failed" >&2; exit 1; }

( cd "$WORK/tls" \
  && openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -subj "/CN=SSH Buddy Test CA" -days 3 2>/dev/null \
  && openssl req -newkey rsa:2048 -nodes -keyout keys.key -out keys.csr -subj "/CN=keys.test" 2>/dev/null \
  && printf 'subjectAltName=DNS:keys.test\nbasicConstraints=CA:FALSE\n' > ext.cnf \
  && openssl x509 -req -in keys.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out keys.crt -days 2 -extfile ext.cnf 2>/dev/null )

docker build -q -t sb-systemd -f "$ROOT/integration/Dockerfile.systemd" "$ROOT/integration" >/dev/null || { echo "image build failed" >&2; exit 1; }
docker image inspect "$PW_IMAGE" >/dev/null 2>&1 || docker pull -q "$PW_IMAGE" >/dev/null
docker image inspect nginx:stable-alpine >/dev/null 2>&1 || docker pull -q nginx:stable-alpine >/dev/null
docker image inspect curlimages/curl:latest >/dev/null 2>&1 || docker pull -q curlimages/curl:latest >/dev/null
cp -r "$ROOT/integration/ui" "$WORK/ui"
docker run --rm -v "$WORK/ui:/ui" -w /ui "$PW_IMAGE" npm install --no-audit --no-fund --silent >/dev/null 2>&1 || { echo "npm install failed" >&2; exit 1; }

PW() { docker run --rm --network "$NET" -e PHASE -e ACTION -e LABEL -e MODE -v "$WORK/ui:/ui" -v "$WORK/shared:/shared" -w /ui "$PW_IMAGE" node "$@"; }
SQL() { docker run --rm -v "$VOL:/data" sb-systemd sqlite3 /data/sshbuddy.db "$@"; }
ui_run() { # script [env...]  -> parses "N/M UI checks passed"
  local out; out="$(PW "$@" 2>&1)"; echo "$out" | grep -E '^(PASS|FAIL)|checks passed|^    ' | head -30
  local p total; p="$(echo "$out" | sed -n 's#^\([0-9]*\)/\([0-9]*\) UI checks passed#\1#p')"; total="$(echo "$out" | sed -n 's#^\([0-9]*\)/\([0-9]*\) UI checks passed#\2#p')"
  if [ -n "$p" ] && [ "$p" = "$total" ]; then PASS=$((PASS + p)); else FAIL=$((FAIL + ${total:-1} - ${p:-0})); PASS=$((PASS + ${p:-0})); fi
}
wait_marker() { for _ in $(seq 1 "$2"); do docker exec "$1" test -e /var/lib/ssh-buddy-agent/bootstrap-complete 2>/dev/null && return 0; sleep 1; done; return 1; }
clone() {
  docker rm -f "$1" >/dev/null 2>&1
  docker run -d --name "$1" --privileged --cgroupns=host --network "$NET" --ip 172.30.0.20 --hostname web1.lab.test \
    --tmpfs /run --tmpfs /tmp -v /sys/fs/cgroup:/sys/fs/cgroup:rw sb-template /sbin/init >/dev/null
}
sshtry() { docker exec sb-client2 ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -i "/tmp/$1" -o ConnectTimeout=5 root@127.0.0.1 echo login-ok 2>&1 | tail -1; }

# --------------------------------------------------------------------------- server
log "server: network, app (Production, fresh database), nginx with TLS"
docker network create --subnet 172.30.0.0/24 "$NET" >/dev/null
docker volume create "$VOL" >/dev/null
docker run -d --name sb-app --network "$NET" --ip 172.30.0.10 -v "$WORK/app:/opt/app:ro" -v "$WORK/releases:/releases:ro" -v "$VOL:/data" \
  -e ASPNETCORE_ENVIRONMENT=Production -e ASPNETCORE_URLS=http://0.0.0.0:5000 "-e=ConnectionStrings__Default=Data Source=/data/sshbuddy.db" \
  -e DataProtection__KeysDirectory=/data/keys -e App__PublicBaseUrl=https://keys.test -e AllowedHosts=keys.test \
  -e ReverseProxy__KnownNetworks__0=172.30.0.0/24 -e Agent__ReleaseDirectory=/releases -w /opt/app debian:trixie sleep infinity >/dev/null
docker exec sb-app /opt/app/SshBuddy.Web migrate >/dev/null
printf 'integration test passphrase\n' | docker exec -i sb-app /opt/app/SshBuddy.Web admin create --email admin@test.example --password-stdin >/dev/null
docker exec -d sb-app sh -c '/opt/app/SshBuddy.Web > /data/server.log 2>&1'
docker run -d --name sb-nginx --network "$NET" --ip 172.30.0.11 --network-alias keys.test -v "$ROOT/integration/nginx.conf:/etc/nginx/conf.d/default.conf:ro" -v "$WORK/tls:/tls:ro" nginx:stable-alpine >/dev/null
for _ in $(seq 1 40); do
  docker run --rm --network "$NET" -v "$WORK/tls/ca.crt:/ca.crt:ro" curlimages/curl:latest --cacert /ca.crt -sf -o /dev/null https://keys.test/api/authorized-keys && break; sleep 1
done
check "HTTPS API reachable through nginx with the test CA" docker run --rm --network "$NET" -v "$WORK/tls/ca.crt:/ca.crt:ro" curlimages/curl:latest --cacert /ca.crt -sf https://keys.test/api/agent/manifest.txt
check "plain HTTP at the proxy is redirected to HTTPS, not served" bash -c "[ \"\$(docker run --rm --network $NET curlimages/curl:latest -s -o /dev/null -w '%{http_code}' http://keys.test/api/authorized-keys)\" = 301 ]"

log "UI phase 1: login, keys, template credential"
ui_run ui1.mjs

# --------------------------------------------------------------------------- template + first clone
log "template: install the bootstrap with the credential from the UI, check hygiene, commit"
docker run -d --name sb-builder sb-systemd sleep infinity >/dev/null
docker cp "$WORK/tls/ca.crt" sb-builder:/ca.crt; docker cp "$ROOT/template" sb-builder:/template
docker exec -i sb-builder /template/install-into-template.sh https://keys.test --interval 1m --ca /ca.crt < "$WORK/shared/template-token" >/dev/null 2>&1
check "prepare-template flags host keys and machine-id until cleaned" bash -c "! docker exec sb-builder /template/prepare-template.sh"
docker exec sb-builder sh -c ':> /etc/machine-id; rm -f /etc/ssh/ssh_host_*'
check "prepare-template reports a clean template" docker exec sb-builder /template/prepare-template.sh
docker commit sb-builder sb-template >/dev/null; docker rm -f sb-builder >/dev/null

log "first container boots from the template (real systemd)"
clone sb-client
if wait_marker sb-client 150; then ok "bootstrap completed (agent downloaded, installed, enrolled, first sync, timer, marker)"; else bad "bootstrap did not complete"; docker exec sb-client journalctl -u ssh-buddy-bootstrap --no-pager | tail -15; fi
check "agent binary runs and reports its version" docker exec sb-client /usr/local/sbin/ssh-buddy-agent version
check "effective sshd AuthorizedKeysFile includes recovery + managed files" docker exec sb-client sh -c "sshd -T -C user=root,host=localhost,addr=127.0.0.1 | grep -i '^authorizedkeysfile .*\.ssh/authorized_keys .*/etc/ssh/authorized_keys.d/%u-managed'"
check "managed file is root:root 0644 in a 0755 directory" docker exec sb-client sh -c '[ "$(stat -c "%a %U:%G" /etc/ssh/authorized_keys.d/root-managed)" = "644 root:root" ] && [ "$(stat -c %a /etc/ssh/authorized_keys.d)" = 755 ]'
check "machine credential file is root-only (0600)" docker exec sb-client sh -c '[ "$(stat -c %a /var/lib/ssh-buddy-agent/machine-credential)" = 600 ]'
check "template contained no per-machine state: marker created at runtime only" docker exec sb-client test -e /var/lib/ssh-buddy-agent/bootstrap-complete

log "UI phase 2a: Machines page for the healthy container, removal dialog"
PHASE=a ui_run ui2.mjs

# --------------------------------------------------------------------------- rebuilt container
log "the container is rebuilt: same hostname, fresh disk"
docker rm -f sb-client >/dev/null; clone sb-client2
# the bootstrap runs in the background: the machine finishes booting while it is still retrying
timeout 40 bash -c "until [ \"\$(docker exec sb-client2 systemctl is-active multi-user.target 2>/dev/null)\" = active ]; do sleep 1; done" \
  && ok "multi-user.target reached while the bootstrap has not completed (boot is not delayed)" || bad "boot was held up by the bootstrap"
check "bootstrap has not completed yet (it is refused until permitted)" bash -c "! docker exec sb-client2 test -e /var/lib/ssh-buddy-agent/bootstrap-complete"
log "UI phase 2b: refused enrollment is shown as re-enrollment requested; permit"
PHASE=b ui_run ui2.mjs
if wait_marker sb-client2 180; then ok "rebuilt container finished bootstrap only after the permit"; else bad "rebuilt container never completed"; docker exec sb-client2 journalctl -u ssh-buddy-bootstrap --no-pager | tail -12; fi
log "UI phase 2c: healthy again, permit consumed, audit trail"
PHASE=c ui_run ui2.mjs
check "bootstrap failed (and retried) at least once before the permit" bash -c "docker exec sb-client2 journalctl -u ssh-buddy-bootstrap --no-pager | grep -q 'will retry'"

# --------------------------------------------------------------------------- real ssh, outage, stale
log "real ssh: add a key in the UI, wait for the timer, log in, revoke, wait, log in again"
docker exec sb-client2 sh -c 'ssh-keygen -q -t ed25519 -N "" -f /tmp/op -C operator; ssh-keygen -q -t ed25519 -N "" -f /tmp/rec -C recovery; install -d -m 700 /root/.ssh; cp /tmp/rec.pub /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys'
docker exec sb-client2 cat /tmp/op.pub > "$WORK/shared/test.pub"
[ "$(sshtry op)" = "login-ok" ] && bad "operator key worked before it was added" || ok "operator key refused before it is added"
ACTION=add LABEL=operator-key ui_run ui3.mjs
timeout 170 bash -c "until docker exec sb-client2 grep -q operator-key /etc/ssh/authorized_keys.d/root-managed; do sleep 3; done" && ok "timer delivered the new key" || bad "key never arrived"
[ "$(sshtry op)" = "login-ok" ] && ok "ssh login with the UI-added key works" || bad "ssh login with the UI-added key failed"
[ "$(sshtry rec)" = "login-ok" ] && ok "recovery key works" || bad "recovery key failed"
ACTION=revoke LABEL=operator-key ui_run ui3.mjs
timeout 170 bash -c "until ! docker exec sb-client2 grep -q operator-key /etc/ssh/authorized_keys.d/root-managed; do sleep 3; done" && ok "next sync removed the revoked key" || bad "revoked key still present"
[ "$(sshtry op)" = "login-ok" ] && bad "revoked key still logs in" || ok "revoked key is refused after the next sync"
[ "$(sshtry rec)" = "login-ok" ] && ok "recovery key still works after revocation" || bad "recovery key failed"
check "recovery file is byte-identical to the original" docker exec sb-client2 cmp /root/.ssh/authorized_keys /tmp/rec.pub

log "server outage: keys survive, failures are visible, and recovery is timer-driven (no manual start)"
BEFORE="$(docker exec sb-client2 sha256sum /etc/ssh/authorized_keys.d/root-managed)"
runs() { docker exec sb-client2 journalctl -u ssh-buddy-agent --no-pager -o cat | grep -c "$1" || true; }
FAILS_BEFORE="$(runs 'ERROR: sync failed')"
docker stop sb-nginx >/dev/null
timeout 170 bash -c "until [ \"\$(docker exec sb-client2 journalctl -u ssh-buddy-agent --no-pager -o cat | grep -c 'ERROR: sync failed')\" -gt $FAILS_BEFORE ]; do sleep 3; done" \
  && ok "a timer-driven run failed during the outage" || bad "no timer-driven failure observed during the outage"
[ "$(docker exec sb-client2 systemctl is-failed ssh-buddy-agent.service)" = failed ] && ok "the failure is visible (unit failed)" || bad "unit is not shown as failed"
[ "$(docker exec sb-client2 sha256sum /etc/ssh/authorized_keys.d/root-managed)" = "$BEFORE" ] && ok "managed file untouched during the outage" || bad "managed file changed during the outage"
check "the timer is still scheduled after a failed run" bash -c "docker exec sb-client2 systemctl list-timers ssh-buddy-agent.timer --no-pager | grep -q ssh-buddy-agent.timer"
OKS_BEFORE="$(runs 'keys unchanged')"
docker start sb-nginx >/dev/null
timeout 170 bash -c "until [ \"\$(docker exec sb-client2 journalctl -u ssh-buddy-agent --no-pager -o cat | grep -c 'keys unchanged')\" -gt $OKS_BEFORE ]; do sleep 3; done" \
  && ok "the next timer run succeeded by itself once the server was back" || bad "the timer did not recover after the outage"
[ "$(docker exec sb-client2 systemctl is-failed ssh-buddy-agent.service)" != failed ] && ok "unit no longer failed after recovery" || bad "unit still failed after recovery"

log "stale -> healthy: back-date the last contact by five days, then let the machine's own timer check in"
SQL "update Machines set LastContactUtc = datetime('now','-5 days')" >/dev/null
MODE=Stale ui_run ui4.mjs
MODE=Healthy ui_run ui4.mjs
check "the stale machine was neither deleted nor revoked" bash -c "[ \"\$(docker run --rm -v $VOL:/data sb-systemd sqlite3 /data/sshbuddy.db 'select count(*) from Machines where RevokedUtc is null')\" = 1 ]"

# --------------------------------------------------------------------------- permit recovers a running machine
log "removed but still running: its own next runs ask to re-enroll; the permit alone is enough (no file is touched on the machine)"
OLDHASH="$(docker exec sb-client2 sha256sum /var/lib/ssh-buddy-agent/machine-credential)"
PHASE=remove ui_run ui5.mjs
PHASE=requested ui_run ui5.mjs
PHASE=healthy ui_run ui5.mjs
[ "$(docker exec sb-client2 sha256sum /var/lib/ssh-buddy-agent/machine-credential)" != "$OLDHASH" ] && ok "the machine credential was replaced by the agent itself" || bad "credential unchanged"
check "keys kept syncing the whole time (managed file still present)" docker exec sb-client2 test -s /etc/ssh/authorized_keys.d/root-managed
check "journal shows the automatic re-enrollment" bash -c "docker exec sb-client2 journalctl -u ssh-buddy-agent --no-pager -o cat | grep -q 're-enrolled under an administrator permit'"
[ "$(SQL "select count(*) from AuditEvents where Action='MachineReenrolled'")" = 2 ] && ok "audit trail has both permitted re-enrollments (rebuilt container, then the running machine)" || bad "unexpected number of MachineReenrolled events"

# --------------------------------------------------------------------------- secrets
log "secrets: raw credentials must not appear in any log or in the database"
TOK="$(cat "$WORK/shared/template-token")"; CRED="$(docker exec sb-client2 cat /var/lib/ssh-buddy-agent/machine-credential)"
count() { grep -c -F -e "$TOK" -e "$CRED" || true; }
[ "$(docker exec sb-app cat /data/server.log | count)" = 0 ] && ok "server log has no raw credential" || bad "server log contains a credential"
[ "$(docker run --rm -v "$VOL:/data" sb-systemd sqlite3 /data/sshbuddy.db .dump | count)" = 0 ] && ok "database has no raw credential (hashes only)" || bad "database contains a credential"
[ "$(docker exec sb-client2 journalctl --no-pager | count)" = 0 ] && ok "client journal has no raw credential" || bad "client journal contains a credential"
[ "$(docker logs sb-nginx 2>&1 | count)" = 0 ] && ok "nginx logs have no raw credential" || bad "nginx logs contain a credential"
[ "$(echo -n "$CRED" | sha256sum | cut -d' ' -f1)" = "$(SQL 'select CredentialHash from Machines')" ] && ok "stored hash equals SHA-256 of the machine credential" || bad "credential hash mismatch"

printf '\n==================== integration summary: %s passed, %s failed ====================\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
