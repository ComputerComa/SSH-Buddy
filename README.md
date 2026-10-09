# SSH Buddy

A small self-hosted app that keeps one central list of approved SSH **public** keys, and a dashboard of the machines that use it.
Every Linux machine pulls the same list on a timer and writes it to `/etc/ssh/authorized_keys.d/root-managed`.

- **Admin UI** (Blazor, Bootstrap): keys (add / revoke / reactivate), one-time tokens for uploading a public key, **Machines** dashboard, **template enrollment credentials**, audit trail.
- **`GET /api/authorized-keys`**: public, anonymous, plain-text `authorized_keys` list with `ETag` (also `HEAD`).
- **`POST /api/keys/enroll`**: a device uploads its `.pub` file with a short-lived single-use token.
- **Go agent** (`agent/`): a static binary that syncs keys, enrolls the machine and reports status. Served by SSH Buddy itself at `/api/agent/*`.
- **`POST /api/machines/enroll`, `POST /api/machines/checkin`**: machine enrollment (shared template credential) and reporting (per-machine credential). Completely separate from the key-upload tokens.
- **LXC template bootstrap** (`template/`): bakes in the URL, your CA and a shared enrollment credential; each clone downloads the agent on first boot, enrolls and starts syncing.
- **Legacy shell client** (`client/`): the original minimal sync script; no reporting. Superseded by the agent (installing the agent disables its timer).

Not included, on purpose: SSH certificates, per-host key assignment, a bastion, multi-tenancy, DNS registration and e-mail notification (the server has the hooks for them; see [docs/agent.md](docs/agent.md)).

## Stack and versions

| Component | Version |
|---|---|
| .NET SDK / runtime | **10.0.401 / 10.0.12** (LTS), pinned by `global.json` (`rollForward: latestFeature`) |
| ASP.NET Core (Blazor Web App, Interactive Server) | 10.0.12 |
| EF Core + SQLite, Identity EF stores, EF Design | **10.0.12** (all `Microsoft.*` packages match the runtime) |
| `dotnet-ef` local tool | 10.0.12 (`dotnet-tools.json`) |
| Go agent toolchain | **Go 1.26.9** (pinned `toolchain` line) with `golang.org/x/crypto v0.58.0`; targets need no Go |
| Bootstrap | the copy shipped by the project template (`wwwroot/lib/bootstrap`) |

## Layout

```
src/SshBuddy.Web/   app: Components/ (Blazor), Services/ (all business logic), Endpoints/, Data/ (+ Migrations)
tests/SshBuddy.Tests  xUnit: keys, machines, HTTP auth/contracts, release serving, legacy client script
agent/              Go agent: internal/keys, internal/agent (sync, enroll, report), internal/install, build.sh
template/           first-boot bootstrap + unit, install-into-template.sh, prepare-template.sh
client/             legacy shell client (no reporting)
deploy/             systemd unit, env example, nginx example, backup script
docs/               deployment.md, template.md, agent.md, agent-release.md, client.md
```

`KeyService`, `EnrollmentService`, `AuthorizedKeysService`, `PublicKeyParser`, `TemplateCredentialService`, `MachineService`
and `AgentReleaseService` hold the logic; the Blazor pages and the API endpoints are thin callers of the same services.

## Develop

```bash
dotnet tool restore
dotnet run --project src/SshBuddy.Web -- migrate                       # creates App_Data/sshbuddy.db
printf '%s\n' 'a-long-passphrase-here' | dotnet run --project src/SshBuddy.Web -- admin create --email you@example.com --password-stdin
dotnet run --project src/SshBuddy.Web                                   # http://localhost:5094 (see launchSettings)
dotnet test                                                             # includes the client-script tests (needs bash)
(cd agent && go test -race ./...)                                       # the agent suite (real TLS test server)
(cd agent && ./build.sh --verify)                                       # release build + reproducibility check
```

Data (`App_Data/`) and `*.env` files are git-ignored. Nothing secret lives in the repo.

New migration after changing the model:

```bash
dotnet dotnet-ef migrations add <Name> --project src/SshBuddy.Web --output-dir Data/Migrations
```

## First-run administrator

There is no registration page and no default account. Create the single administrator on the server:

```bash
cd /opt/ssh-buddy && set -a && . /etc/ssh-buddy/ssh-buddy.env && set +a
runuser -u ssh-buddy -- ./SshBuddy.Web admin create --email you@example.com
```

It prompts twice for a password (minimum 12 characters). For scripted use, pass `--password-stdin` and pipe the password in.
`admin create` refuses to run once an administrator exists; use `admin reset-password --email …` to recover access.

## Machines, templates and the agent (summary)

1. **Machines → Template credentials**: create a credential for your LXC template (shown once, stored hashed). It can only enroll machines.
2. Build the template with [`template/install-into-template.sh`](docs/template.md) and publish an agent release ([docs/agent-release.md](docs/agent-release.md)).
3. Each clone's `ssh-buddy-bootstrap.service` downloads the agent (size + SHA-256 verified, atomic install), installs a validated sshd drop-in,
   runs the first sync, registers under its FQDN, then enables the timer.
4. **Machines** shows Healthy / Sync error / Stale (default 3 days) / Removed, with last contact, last successful sync, IP, agent version and key-list revision.
5. A hostname that is already enrolled is never given a new credential on request. A rebuilt container is refused and shown as
   "re-enrollment requested"; **Permit re-enrollment** allows exactly one enrollment within a time window. A removed machine that is still running asks to
   re-enroll on every run and recovers by itself once permitted. The bootstrap runs in the background and never delays boot.
   Removing a machine disables its reporting only, not any SSH key or key already on the machine.

## Security notes

- Everything is private by default (fallback authorization policy); only `/login`, static assets, the two API endpoints, and error pages are anonymous.
- Login and logout are antiforgery-protected form posts; login is rate limited (5/min/IP, configurable) on top of Identity lockout (5 failures, 15 min). Enrollment is rate limited (10/min/IP).
- Enrollment tokens: 256-bit random, stored as SHA-256 only, sent in `Authorization: Bearer`, consumed by a conditional `UPDATE` in the same transaction as the key insert. Bad input or a duplicate key rolls back and leaves the token usable until it expires.
- The server stores only `algorithm + key blob`; the submitted comment is discarded. Labels are rendered into the list as a sanitized comment (printable ASCII, no spaces), so nothing user-controlled can add `authorized_keys` options.
- In Production, `/api/*` over plain HTTP is answered `403` rather than redirected (a redirected POST would already have leaked the token). The UI redirects to HTTPS and uses `Secure` cookies.
- The Bearer token appears in the enrolling machine's process list and shell history; this is acceptable only because tokens are short-lived and single-use.
- Do not enable HTTP request logging on the reverse proxy for `/api/keys/enroll`, `/api/machines/*` with headers.
- Three unrelated credential kinds exist and none works for another's purpose: the single-use key-upload token (`sbe_`), the shared template credential (`sbt_`, enroll machines only) and the per-machine credential (`sbm_`, report only). All are stored as SHA-256 hashes; the machine credential and nonce live in a root-only file on the machine.
- The template credential is *shared by design*: anyone who can read it inside a container can enroll **new** hostnames. It cannot take over an existing hostname, add keys, or read anything. Revoke it in the UI if it leaks (existing machines are unaffected).
- Agent binaries are verified by a checksum served from the same host. That is integrity, **not** an independent signature; authenticity rests on TLS to your server and the CA baked into the template.

More: [docs/deployment.md](docs/deployment.md), [docs/client.md](docs/client.md).

## Verification status

**Run and passing (this repository, this machine):**

* **Server ⇔ agent key contract.** The agent rejects a whole key list if any line fails `x/crypto/ssh` parsing, so the server must never store a key the agent would reject. `testdata/key-corpus.txt` (real keys plus crafted ones: off-curve ECDSA points, even/oversized RSA exponents, non-minimal or negative integers, truncated/trailing data) holds the agent's verdicts; both `go test` and `dotnet test` assert them. Writing it found 14 cases the server used to accept and the agent rejects; the server is now exactly as strict. Stored keys that fail today's validation are also withheld from the distributed list.
* **Upgrading a slice-1 database:** a test migrates to the original `Initial` migration, inserts keys and audit rows, runs the full migration, and asserts the rows and the served list/ETag are unchanged.

* `dotnet test`: .NET suite (keys, machines, enrollment rules, hostname normalization/collisions, interrupted enrollment, permits,
  revocation, stale/sync-error/healthy transitions, status, release serving and traversal, HTTP contracts and cross-credential
  rejection, rate limits, Production pipeline, legacy client script).
* `cd agent && go test -race ./...`: real key parsing (all allowed types; options, certificates, DSA, short RSA, truncated/trailing data,
  non-canonical base64, CR/NUL and oversize rejected), atomic replacement (inode changes, no temp files, 0644/0755), empty list,
  ETag trust only for validated unchanged local contents, network/TLS/HTTP failures keep the old file, certificate verification not
  disabled, overlapping runs, reporting after unchanged/failed syncs, reporting failure never undoing a key update, nonce-based
  recovery of a lost enrollment response, no automatic re-enrollment after `401`, no secrets in logs, FQDN detection, installer
  rollback (previous drop-in restored exactly, overridden `AuthorizedKeysFile` = failure, missing host keys, legacy timer).
* `govulncheck` on the agent: 0 affecting vulnerabilities with Go 1.26.9 / x/crypto 0.58.0 (it found 36 with the Go 1.24.4 that was installed locally).
* `./build.sh --verify`: two builds, and a build from a different directory, were byte-identical.
* **`integration/run.sh`: 56 checks, 0 failures** from a clean start from a clean start (see [integration/README.md](integration/README.md)). It covers: Docker (nginx with TLS from a test CA → app; Debian 13 containers with **systemd as PID 1**): template build and hygiene
  check; first-boot bootstrap from a committed template image; agent download + checksum + atomic install; sshd drop-in validated;
  first sync + enrollment; timer-driven runs (304 path); real `ssh` login with a key added in the UI and refused after revocation;
  recovery key untouched; server outage keeps keys and recovers; refused enrollment of a rebuilt container, "re-enrollment requested",
  Permit, completion; stale → healthy; recorded client IP is the container's, not the proxy's; no raw credential in the server log, database,
  client journal or nginx log.
* **UI in a real browser** (Playwright/Chromium, 24 checks across four scripts): login/logout, anonymous redirects, add/duplicate/private-key/option
  rejection, revoke/reactivate, key-upload token page, template credential shown once, Machines page (counters, IP, version, revision),
  removal confirmation text and cancel, removal, re-enrollment flag and permit, audit page.

**Not verified:**

* A real **Proxmox LXC** host: `network-online.target` behaviour, how Proxmox writes the hostname and `/etc/hosts`, unprivileged-container
  restrictions. Docker containers stood in for LXC; the only failed unit in them was `systemd-modules-load` (a container artefact).
* **arm64**: the arm64 binary is built, checksummed and served, but was not executed (no arm64 host or emulator here).
* An **interrupted enrollment against the live stack** (response lost on the wire): covered by unit and HTTP tests on both sides, not by a fault-injected end-to-end run.
* The **reverse proxy** was nginx in Docker only; Caddy/Traefik/HAProxy and a proxy on a separate physical host are untested.
* A **stale threshold of days in real time** (the integration run back-dated the contact timestamp instead of waiting three days).
* **Technitium DNS registration and e-mail notifications**: intentionally not implemented; only the extension points exist.
