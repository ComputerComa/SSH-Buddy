# SSH Buddy

A small self-hosted app that keeps one central list of approved SSH **public** keys.
Every Linux machine pulls the same list on a timer and writes it to
`/etc/ssh/authorized_keys.d/root-managed`.

- **Admin UI** (Blazor, Bootstrap): add, revoke and reactivate keys, generate one-time enrollment tokens, view an audit trail.
- **`GET /api/authorized-keys`**: public, anonymous, plain-text `authorized_keys` list with `ETag`.
- **`POST /api/keys/enroll`**: a device submits its `.pub` file with a short-lived single-use token.
- **Linux client** (`client/`): script + systemd timer, installable into an LXC template with no per-machine credentials.

Not included, on purpose: SSH certificates, a bastion, per-server registration, host groups, multi-tenancy.

## Stack and versions

| Component | Version |
|---|---|
| .NET SDK / runtime | **10.0.401 / 10.0.12** (LTS), pinned by `global.json` (`rollForward: latestFeature`) |
| ASP.NET Core (Blazor Web App, Interactive Server) | 10.0.12 |
| EF Core + SQLite, Identity EF stores, EF Design | **10.0.12** (all `Microsoft.*` packages match the runtime) |
| `dotnet-ef` local tool | 10.0.12 (`dotnet-tools.json`) |
| Bootstrap | the copy shipped by the project template (`wwwroot/lib/bootstrap`) |

## Layout

```
src/SshBuddy.Web/   app: Components/ (Blazor), Services/ (all business logic), Endpoints/, Data/ (+ Migrations)
tests/SshBuddy.Tests  xUnit: validation, duplicates, token expiry/concurrency, HTTP auth, client script
client/             ssh-buddy-sync, systemd service + timer, sshd drop-in, install.sh
deploy/             systemd unit, env example, nginx example, backup script
docs/               deployment.md, client.md
```

`KeyService`, `EnrollmentService`, `AuthorizedKeysService` and `PublicKeyParser` hold the logic; the Blazor pages and the API endpoints are thin callers of the same services.

## Develop

```bash
dotnet tool restore
dotnet run --project src/SshBuddy.Web -- migrate                       # creates App_Data/sshbuddy.db
printf '%s\n' 'a-long-passphrase-here' | dotnet run --project src/SshBuddy.Web -- admin create --email you@example.com --password-stdin
dotnet run --project src/SshBuddy.Web                                   # http://localhost:5094 (see launchSettings)
dotnet test                                                             # includes the client-script tests (needs bash)
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

## Security notes

- Everything is private by default (fallback authorization policy); only `/login`, static assets, the two API endpoints, and error pages are anonymous.
- Login and logout are antiforgery-protected form posts; login is rate limited (5/min/IP, configurable) on top of Identity lockout (5 failures, 15 min). Enrollment is rate limited (10/min/IP).
- Enrollment tokens: 256-bit random, stored as SHA-256 only, sent in `Authorization: Bearer`, consumed by a conditional `UPDATE` in the same transaction as the key insert. Bad input or a duplicate key rolls back and leaves the token usable until it expires.
- The server stores only `algorithm + key blob`; the submitted comment is discarded. Labels are rendered into the list as a sanitized comment (printable ASCII, no spaces), so nothing user-controlled can add `authorized_keys` options.
- In Production, `/api/*` over plain HTTP is answered `403` rather than redirected (a redirected POST would already have leaked the token). The UI redirects to HTTPS and uses `Secure` cookies.
- The Bearer token appears in the enrolling machine's process list and shell history; this is acceptable only because tokens are short-lived and single-use.
- Do not enable HTTP request logging on the reverse proxy for `/api/keys/enroll` with headers.

More: [docs/deployment.md](docs/deployment.md), [docs/client.md](docs/client.md).
