# Deployment: Debian 13 LXC behind an HTTPS reverse proxy

## 1. Get a server bundle

Either download the latest release, or build one (on a machine with the .NET 10 SDK and Go; see [agent-release.md](agent-release.md)):

```bash
curl -fsSLO https://github.com/ComputerComa/SSH-Buddy/releases/latest/download/ssh-buddy-server-linux-x64.tar.gz
# or: VERSION=1.2.0 ./build.sh   ->  dist/ssh-buddy-server-linux-x64.tar.gz
```

The bundle is self-contained (no .NET in the container) and carries the agent release this server version serves.

## 2. Install in the container

Inside the Debian 13 LXC, as root:

```bash
tar xzf ssh-buddy-server-linux-x64.tar.gz
ssh-buddy-server-linux-x64/install.sh
```

`install.sh` installs `ca-certificates`, `libssl3t64` (a .NET runtime dependency) and `sqlite3` (for backups) if missing,
creates the `ssh-buddy` system user, `/var/lib/ssh-buddy` (data) and `/etc/ssh-buddy/ssh-buddy.env` (from the example,
`root:ssh-buddy 0640`), installs the app in `/opt/ssh-buddy`, publishes the bundled agent release, installs the
`ssh-buddy` operator command and `ssh-buddy-backup`, and enables `ssh-buddy.service`. It does not start the service while
the config still names `keys.home.example`:

```bash
$EDITOR /etc/ssh-buddy/ssh-buddy.env        # host name, base URL, proxy address
systemctl start ssh-buddy
```

To ship a ready config instead, put a filled-in `ssh-buddy.env` next to `install.sh` in the unpacked bundle (or in
`deploy/ssh-buddy.env` before `./build.sh`; it is gitignored); `install.sh` installs it and starts the service.

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
| `Agent__ReleaseDirectory` | where agent releases are published ([agent-release.md](agent-release.md)) |
| `Agent__Version` | optional: serve this version instead of the highest complete one |
| `Machines__StaleAfterDays` | machine shown as stale after this long without contact (default 3) |
| `Machines__ReenrollPermitMinutes` | lifetime of "Permit re-enrollment" (default 240) |
| `RateLimits__MachineEnrollPerMinute`, `RateLimits__CheckInPerMinute` | defaults 60 per IP and 20 per machine credential |

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

### Without TLS (plain HTTP)

On a network you trust, you can skip certificates and the reverse proxy entirely: the app listens on port 80 itself and
the agents talk plain HTTP. In `ssh-buddy.env`:

```
ASPNETCORE_URLS=http://0.0.0.0:80
App__PublicBaseUrl=http://keys.home.example
AllowedHosts=keys.home.example
Security__RequireHttps=false
```

and build the template with `http://keys.home.example` (no `--ca`). `Security__RequireHttps=false` lets the API answer plain
HTTP, stops the redirect to HTTPS and drops the `Secure` flag from the login cookie (a browser discards a `Secure` cookie set
over http, so login would not stick). The unit has `CAP_NET_BIND_SERVICE` so the service user can bind port 80.

What you give up: anyone who can watch or redirect traffic on that network can read the admin password, session cookie and
credentials, and can answer the agents in the server's place, which means choosing the keys every machine accepts for root.
Each scheme is taken literally: an `https://` URL is always verified, `http://` is never upgraded or downgraded.

**Moving to TLS later** (for example with certificates from step-ca): serve HTTPS (a reverse proxy, or the app itself with
`ASPNETCORE_URLS=https://0.0.0.0:443`, `Kestrel__Certificates__Default__Path` and `__KeyPath` pointing at the certificate and key),
rebuild the template with `https://` and `--ca root_ca.crt`, and change `url=` in `/etc/ssh-buddy/agent.conf` on existing containers
(`pct exec <id> -- sed -i 's#^url=http://#url=https://#' /etc/ssh-buddy/agent.conf`; they also need the root CA in their trust
store). Keep `Security__RequireHttps=false` until every container has switched, then remove it.

## 3. The first administrator, upgrades

```bash
ssh-buddy admin create --email you@example.com
```

`ssh-buddy` runs the app's commands (`migrate`, `admin create`, `admin reset-password`, `version`) as the service user with
the settings from `ssh-buddy.env`, read the way systemd reads them. (Sourcing the file with `set -a; . ssh-buddy.env` does
**not** work: the shell cuts `ConnectionStrings__Default=Data Source=...` at the space.)

`ExecStartPre` re-runs `migrate` on every service start. **Upgrade** by running `install.sh` from a newer bundle: it copies
the database to `/var/backups/ssh-buddy` (`VACUUM INTO`), replaces `/opt/ssh-buddy`, keeps the config and data, publishes
the new agent release, and restarts the service, which migrates. Migrations are EF Core migrations (Identity tables
included); the app never calls `EnsureCreated`. The database runs in WAL mode.

Smoke test:

```bash
curl -i https://keys.home.example/api/authorized-keys     # 200, empty body, ETag header
curl -s https://keys.home.example/api/agent/manifest.txt  # the bundled agent: linux-amd64 and linux-arm64
```

Then follow [template.md](template.md) to create the template credential and the LXC template.
The reverse proxy must forward the **real client address** (`X-Forwarded-For`) and you must list the proxy in `ReverseProxy__KnownProxies`
or `__KnownNetworks`: the Machines page records that address, and without trust configured it would show the proxy's address for every machine.

## 4. Backups

The state is one SQLite file (keys, machines, hashed credentials, audit) plus the data-protection keys; agent releases are rebuilt from source. `deploy/backup.sh` takes a consistent online copy
(`VACUUM INTO`, safe while the app runs) and prunes copies older than 30 days:

```bash
ssh-buddy-backup /var/backups/ssh-buddy          # installed by install.sh; run from cron or a systemd timer, then copy off the container
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
