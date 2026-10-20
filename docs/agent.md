# The SSH Buddy agent

`ssh-buddy-agent` is a static Go binary. It keeps `/etc/ssh/authorized_keys.d/root-managed` in sync with the SSH Buddy
server, registers the machine, and reports status. It replaces the older shell client (see [client.md](client.md)).

```
ssh-buddy-agent sync       one cycle: synchronize keys, then report (run by the systemd timer)
ssh-buddy-agent install    write the sshd drop-in + systemd units, transactionally (run by the bootstrap)
ssh-buddy-agent version
```

Files on a machine:

| Path | Purpose | Mode |
|---|---|---|
| `/usr/local/sbin/ssh-buddy-agent` | the binary | 0755 |
| `/etc/ssh-buddy/agent.conf` | `url=` (https origin, or http if you run without TLS), `interval=`, optional `fqdn=` | 0644 |
| `/etc/ssh-buddy/enroll-token` | the **shared template credential** (can only enroll machines) | 0600 |
| `/var/lib/ssh-buddy-agent/` | per-machine state, root only | 0700 |
| `…/machine-credential` | this machine's own reporting credential | 0600 |
| `…/enroll-nonce` | proof-of-requester for retrying an interrupted enrollment; removed after the first successful check-in | 0600 |
| `…/state.json` | the ETag of the applied list and the SHA-256 of the exact bytes written | 0600 |
| `…/bootstrap-complete` | written by the bootstrap after the first successful sync + registration | 0644 |
| `/etc/ssh/authorized_keys.d/root-managed` | the managed key list | 0644, root:root (directory 0755) |
| `/etc/ssh/sshd_config.d/10-ssh-buddy.conf` | `AuthorizedKeysFile` drop-in | 0644 |

## One `sync` run

1. **Lock** (`flock` on `/run/ssh-buddy-agent.lock`, non-blocking). A second concurrent run exits with code 4 and touches nothing.
2. **Synchronize keys** (independent of everything that follows):
   * `GET /api/authorized-keys` over HTTPS with normal certificate verification against the system CA store, TLS ≥ 1.2
     (or plain HTTP when `url=` says `http://`; see [deployment.md](deployment.md#without-tls-plain-http)),
     10 s connect / 10 s handshake / 15 s first byte / 30 s total, no redirects, no proxy, 1 MiB cap.
   * `If-None-Match` is sent **only if** the managed file exists, is a regular file (not a symlink), still validates as a key
     list, and hashes to exactly what the cached ETag described. Anything else (file edited, deleted, corrupted, state missing)
     means an unconditional fetch. A `304` to an unconditional request is an error.
   * A `200` body is validated line by line with `golang.org/x/crypto/ssh` (real key parsing, not a regex): only
     `ssh-ed25519`, `ssh-rsa` (≥ 2048 bits), `ecdsa-sha2-nistp256/384/521`, `sk-ssh-ed25519@openssh.com`,
     `sk-ecdsa-sha2-nistp256@openssh.com`; no options, no certificates, no DSA, canonical base64, no trailing bytes, ASCII
     single-word comments, final newline required, no blank lines/CR/NUL. An **empty** `200` is valid and clears the file.
   * If the content differs, it is written to a temp file in the same directory, fsynced, `chmod 0644`, `chown root:root`,
     renamed over `root-managed`, and the directory is fsynced. Unchanged content is never rewritten; mode/ownership of the file
     and the directory (0755) are repaired even on `304`.
   * The state file is written after the file and **before** reporting, so a reporting failure cannot affect it.
   * On any failure the managed file and the state are left exactly as they were. `/root/.ssh/authorized_keys` is never touched.
3. **Report** (never influences step 2):
   * Nothing is registered until one key sync has succeeded on this machine.
   * No credential yet → `POST /api/machines/enroll` with the template credential, the FQDN and a random **nonce**
     (persisted with fsync *before* the request). The returned machine credential is saved atomically (0600) before it is used.
   * `POST /api/machines/checkin` with the machine credential on **every** run: agent version, `success`/`error`, the error text,
     and the ETag of the validated contents currently on disk. Failed key syncs are reported too.
   * If the server rejects the stored credential (`401`: the machine was removed or its credential replaced), the agent asks to enroll again, once per run. The server only agrees while an administrator's explicit permit is active; otherwise it answers `409` and records the request, and the old credential file is left untouched.

Exit codes: `0` ok, `1` key sync failed, `2` usage/config, `3` keys fine but reporting failed, `4` another run in progress.
A non-zero exit leaves the systemd unit "failed" (visible with `systemctl --failed`), but the timer keeps running.

## Why the server is as strict as the agent

The agent refuses a key list if **any** line is invalid, and keeps its old file. If the server stored a key the agent rejects, no
machine would receive updates (including revocations) until someone noticed. So the server's `PublicKeyParser` accepts exactly what
`golang.org/x/crypto/ssh` accepts for the allowed key types: points must lie on their curve, RSA exponents must be odd, ≥ 3 and ≤ 24 bits,
integers must be minimally encoded and positive, modulus 2048–16384 bits. `testdata/key-corpus.txt` pins this for both implementations,
and the served list also skips any stored key that fails validation. If you change either parser, regenerate the corpus
(`cd agent && UPDATE_CORPUS=1 go test ./internal/keys -run TestCorpusRegenerate`) and run both test suites.

## FQDN

The machine's identity is its **normalized FQDN** (lower case, one trailing dot removed, IDN converted to ASCII, at least two
labels of letters/digits/hyphen, last label not all digits). The agent derives it without DNS, in this order:
`fqdn=` in `agent.conf` → a hostname that already contains a dot → a dotted name for that host in `/etc/hosts` →
`hostname` + the first `search`/`domain` entry in `/etc/resolv.conf`. If none works, reporting fails with a message telling you to set
`fqdn=` (key sync still works). The server re-validates and is authoritative.

## Enrollment rules (server side)

* A **template credential** (`sbt_…`) can call only `POST /api/machines/enroll`. It cannot add, revoke or upload SSH keys, and
  cannot open the admin UI. It is stored hashed and shown once, when created. Revoking it blocks new enrollments only.
* Enrolling an unknown FQDN creates the machine and returns its credential (`sbm_…`, stored hashed) exactly once.
* A **hostname that already exists is never given a new credential just because a request claims it**:
  * *Lost response*: while the machine has not yet checked in, a retry with the **same nonce** is re-issued a credential (the old
    one stops working). A different nonce is refused with `409`, so a clone sharing the template credential cannot take over a pending identity.
  * *Confirmed or removed machine*: always `409`, until an administrator clicks **Permit re-enrollment**. The permit is single-use
    and expires after `Machines:ReenrollPermitMinutes` (default 240). The refused attempt is recorded (time, address) so the Machines
    page shows "Re-enrollment requested".
* Removing a machine disables its reporting credential and keeps a tombstone row, so an old installation cannot silently re-enroll
  with the shared template credential. **It does not revoke any SSH key or remove keys already on the machine.**
* A machine that is rejected (`401`) keeps syncing keys but cannot report. It asks to enroll on every run (shown as *Re-enrollment requested*). After an administrator clicks **Permit re-enrollment**, its next run enrolls and replaces its credential file by itself; no action on the machine is needed. Nothing else can make the server issue a new credential for an existing hostname.

## Status

| Status | Meaning |
|---|---|
| **Healthy** | contact within the stale threshold, and the last report was a successful sync |
| **Sync error** | it reported an error, or has enrolled but never reported a successful sync. A machine that checks in but cannot sync is **never** healthy |
| **Stale** | no contact for `Machines:StaleAfterDays` (default 3). Wins over the other two. Never deleted or revoked automatically; an authenticated check-in brings it back |
| **Removed** | reporting disabled by an administrator |

All times are server times; the IP is the address the server saw (via the trusted reverse proxy).

## Integration points reserved for later

`MachineService` raises `IMachineEventSink.MachineRegisteredAsync` (new machine or permitted re-enrollment) and
`MachineIpChangedAsync` after the database commit; failures there are logged and ignored. A Technitium DNS updater (credential kept
on the SSH Buddy server) or a notification mailer can implement that interface. Registration is also a distinct audit action
(`MachineRegistered`).
