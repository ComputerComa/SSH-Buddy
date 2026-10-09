# Legacy shell client (Debian 13)

> **Superseded by the Go agent** ([agent.md](agent.md), [template.md](template.md)), which also registers the machine and reports status.
> This shell client is kept for installations that want only the key sync. Do not run both: `ssh-buddy-agent install`
> stops and disables `ssh-buddy-sync.timer` so two writers never fight over `root-managed`.

`ssh-buddy-sync` fetches the global key list and installs it as `/etc/ssh/authorized_keys.d/root-managed`.
It runs as root from a systemd timer; there is no per-machine credential, so it is safe to bake into an LXC template.

## Install

On a machine (or in the template), as root, from this repository's `client/` directory:

```bash
./install.sh https://keys.home.example/api/authorized-keys
```

This:

1. installs `/usr/local/sbin/ssh-buddy-sync` and the `ssh-buddy-sync.service`/`.timer` units;
2. writes `/etc/ssh-buddy/client.env` (only the URL, not a secret);
3. creates `/etc/ssh/authorized_keys.d/`;
4. installs `/etc/ssh/sshd_config.d/10-ssh-buddy.conf`, runs `sshd -t` (rolling back on failure), and reloads `ssh`;
5. enables and starts `ssh-buddy-sync.timer` (when systemd is running; inside a chroot it is only enabled).

Then `systemctl start ssh-buddy-sync.service && journalctl -u ssh-buddy-sync -n 20` for an immediate sync.

### sshd configuration

```
AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2 /etc/ssh/authorized_keys.d/%u-managed
```

This keeps Debian's defaults, so `/root/.ssh/authorized_keys` (your recovery file) is untouched and still honoured, and adds the managed file.
`%u-managed` means only a user who has such a file benefits: just `root-managed` exists, so the global list authorises **root only**, not other accounts.
sshd uses the first value it sees, so the installer checks the effective setting; verify any time with:

```bash
sshd -T -C user=root,host=localhost,addr=127.0.0.1 | grep -i authorizedkeysfile
```

Root login by key must be allowed (`PermitRootLogin prohibit-password`, Debian's default).
The drop-in works because Debian 13's `sshd_config` starts with `Include /etc/ssh/sshd_config.d/*.conf`; make sure no earlier-sorting drop-in sets `AuthorizedKeysFile`.

## Behaviour

| Situation | Result |
|---|---|
| HTTP 200 with valid list | file replaced atomically (temp file in the same directory, `chmod 0644`, `chown root:root`, `rename`) **only if contents differ** |
| HTTP 200, empty body | file is emptied (all keys revoked) |
| Timeout, DNS/TLS error, size cap, any non-200 | existing file kept, unit fails (visible in `systemctl status`) |
| 200 but malformed (HTML captive portal, option-prefixed lines, missing final newline, CR, NUL, certificates, extra whitespace) | existing file kept, unit fails |

Every line must be exactly `algorithm base64 [comment]` with a known key type, so `command=`, `from=` and other options cannot be smuggled in.
curl runs with `--proto =https --tlsv1.2`, 10 s connect / 30 s total timeouts, a 1 MiB cap, no redirects, and normal certificate verification. The script never uses `-k`.

Timer: first run 1 minute after boot, then every 15 minutes with up to 2 minutes of random delay. Edit `ssh-buddy-sync.timer` to change it.

## Revocation semantics

Revoking a key in SSH Buddy removes it from the list at once, but **a machine stops accepting it only after its next successful sync**
(up to ~17 minutes, or never while the server is unreachable, since failed syncs keep the old file).
Revocation does **not** terminate existing SSH sessions; kill them separately if needed (`loginctl terminate-session`, or restart `ssh`).

## LXC template notes

- Run `install.sh` once in the template; clones share the URL and need no secrets, and the timer's random delay spreads their requests.
- The service sets only `NoNewPrivileges`. Stronger sandboxing (`ProtectSystem=`, `PrivateTmp=`) needs mount namespaces, which can fail in unprivileged LXC without nesting (`status=226/NAMESPACE`), so it is deliberately left off.
- The `/etc/ssh/authorized_keys.d` directory is created by the installer, not at service start.
- Clients must trust the certificate on the server URL (public CA, or add your internal CA to the template).
- `install.sh` needs `sshd` (`openssh-server`) and `curl` present.

## Enrolling a new device's key

In the UI: **Enroll → Generate enrollment token**, copy the command, and run it on the device that holds the key.
It looks like (the token is shown once, valid ~15 minutes, single use):

```bash
curl --fail-with-body --silent --show-error --request POST "https://keys.home.example/api/keys/enroll" \
  --header "Authorization: Bearer sbe_…" \
  --data-urlencode "label=$(hostname)" \
  --data-urlencode "publicKey@$HOME/.ssh/id_ed25519.pub"
```

Responses: `201` created, `400` invalid key or label (token still valid), `409` key already registered (token still valid),
`401` token missing/expired/used, `429` rate limited. Private keys are rejected; never submit one.
