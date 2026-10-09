# Deployment: Debian 13 LXC behind an HTTPS reverse proxy

## 1. Build (on your workstation)

A self-contained publish needs no .NET install in the container:

```bash
dotnet publish src/SshBuddy.Web -c Release -r linux-x64 --self-contained -o publish
tar -C publish -czf ssh-buddy.tar.gz .
```

## 2. Container

Inside the Debian 13 LXC (as root; `runuser` keeps the environment, so no `sudo` is needed):

```bash
apt install -y sqlite3 ca-certificates libssl3t64     # sqlite3 is only for backups; OpenSSL is a .NET runtime dependency
useradd --system --home /var/lib/ssh-buddy --shell /usr/sbin/nologin ssh-buddy
install -d -o ssh-buddy -g ssh-buddy -m 0750 /var/lib/ssh-buddy /var/lib/ssh-buddy/keys
install -d -m 0755 /opt/ssh-buddy /etc/ssh-buddy
tar -C /opt/ssh-buddy -xzf ssh-buddy.tar.gz
chmod +x /opt/ssh-buddy/SshBuddy.Web
install -m 0640 -o root -g ssh-buddy deploy/ssh-buddy.env.example /etc/ssh-buddy/ssh-buddy.env
$EDITOR /etc/ssh-buddy/ssh-buddy.env        # host name, base URL, proxy address
install -m 0644 deploy/ssh-buddy.service /etc/systemd/system/
```

The app runs with invariant globalization, so no ICU package is needed. If startup reports a missing native library, install the package it names.

Settings are environment variables (double underscore = `:`), kept in `/etc/ssh-buddy/ssh-buddy.env`, outside source control.

| Variable | Purpose |
|---|---|
| `ConnectionStrings__Default` | SQLite file, e.g. `Data Source=/var/lib/ssh-buddy/sshbuddy.db` |
| `DataProtection__KeysDirectory` | persisted cookie/antiforgery keys (so restarts do not log you out) |
| `App__PublicBaseUrl` | base URL printed in the enrollment `curl` command |
| `AllowedHosts` | restrict to your host name |
| `ReverseProxy__KnownProxies__N` / `__KnownNetworks__N` | **addresses allowed to set `X-Forwarded-*`**; see below |
| `Enrollment__TokenLifetimeMinutes` | default 15 |
| `RateLimits__LoginPerMinute`, `RateLimits__EnrollPerMinute` | defaults 5 and 10 per IP |
| `Security__RequireHttps` | defaults to `true` outside Development |

### Reverse proxy trust

ASP.NET Core ignores `X-Forwarded-Proto/For` unless they come from a trusted proxy (loopback by default).
If nginx/Caddy/Traefik runs in **another** container, add its address, otherwise the app thinks every request is plain HTTP
(API calls are refused with 403) and rate-limits every user as one IP:

```
ReverseProxy__KnownProxies__0=10.0.0.5
```

The proxy must set `X-Forwarded-Proto` and overwrite (not append to) `X-Forwarded-For`; see `deploy/nginx.conf.example`.
If the proxy is on another host, make Kestrel listen on that interface (`ASPNETCORE_URLS=http://10.0.0.20:5000`) and firewall the port to the proxy only.
Terminate TLS with a certificate that clients trust: the Debian clients verify it normally (no `-k`).
For an internal CA, install the CA into the clients' system store (`/usr/local/share/ca-certificates/` + `update-ca-certificates`) in the template.

## 3. Migrations and the first administrator

```bash
cd /opt/ssh-buddy
set -a; . /etc/ssh-buddy/ssh-buddy.env; set +a
runuser -u ssh-buddy -- ./SshBuddy.Web migrate
runuser -u ssh-buddy -- ./SshBuddy.Web admin create --email you@example.com
systemctl daemon-reload && systemctl enable --now ssh-buddy
```

`ExecStartPre` re-runs `migrate` on every service start, so upgrades are: stop, replace `/opt/ssh-buddy`, start.
Migrations are EF Core migrations (Identity tables included); the app never calls `EnsureCreated`.
The database runs in WAL mode.

Smoke test:

```bash
curl -i https://keys.home.example/api/authorized-keys     # 200, empty body, ETag header
```

## 4. Backups

The state is one SQLite file plus the data-protection keys. `deploy/backup.sh` takes a consistent online copy
(`VACUUM INTO`, safe while the app runs) and prunes copies older than 30 days:

```bash
install -m 0755 deploy/backup.sh /usr/local/sbin/ssh-buddy-backup
ssh-buddy-backup /var/backups/ssh-buddy          # run from cron or a systemd timer, then copy off the container
```

Restore: stop the service, copy a `sshbuddy-*.db` to `/var/lib/ssh-buddy/sshbuddy.db` (delete stale `-wal`/`-shm` files),
fix ownership to `ssh-buddy`, start the service. Also snapshot the LXC if your hypervisor supports it.
A lost database is an availability problem, not a lockout: clients keep their last synced file, and
`/root/.ssh/authorized_keys` on each machine remains your recovery path.

## 5. Operating notes

- **Revocation** removes a key from the list immediately, but each machine drops it only after its next successful sync (default: every 15 min plus up to 2 min jitter). It does **not** end sessions that are already open.
- Enrollment tokens expire after 15 minutes and work once. The audit page lists key changes and token creation/use (never token values).
- Logs: `journalctl -u ssh-buddy`. Tokens are never logged; do not turn on header logging in the proxy for `/api/keys/enroll`.
- Signing out ends the cookie; an already-open browser tab keeps its live circuit until closed.
