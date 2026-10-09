# LXC template workflow (Debian 13)

Goal: every container cloned from the template installs the agent, enrolls itself and starts syncing, with nothing
per-machine baked in.

## What goes into the template

| In the template | Why |
|---|---|
| `curl`, `ca-certificates`, `openssh-server` | the bootstrap and sshd |
| your CA certificate in the system store | so TLS to SSH Buddy verifies normally (`/usr/local/share/ca-certificates/*.crt` + `update-ca-certificates`) |
| `/etc/ssh-buddy/agent.conf` | `url=https://keys.home.example`, `interval=5m` |
| `/etc/ssh-buddy/enroll-token` (0600) | the shared **template credential** (enrollment only) |
| `ssh-buddy-bootstrap` + `ssh-buddy-bootstrap.service` (enabled) | first-boot installer |
| `/root/.ssh/authorized_keys` (optional) | your recovery keys; the agent never modifies it |

**Not** in the template: `/var/lib/ssh-buddy-agent/*` (machine credential, nonce, sync state, completion marker),
`/etc/ssh/authorized_keys.d/root-managed`, SSH host keys, a populated `/etc/machine-id`.

## Build the template

1. In the SSH Buddy UI: **Machines → Template credentials → Create credential**. Copy the value (shown once).
2. In a Debian 13 container, as root:

```bash
apt install -y curl ca-certificates openssh-server
# from a checkout of this repository:
printf '%s' 'sbt_…' | ./template/install-into-template.sh https://keys.home.example --interval 5m --ca /path/to/ca.crt
./template/prepare-template.sh            # reports what still needs cleaning
./template/prepare-template.sh --clean    # removes only SSH Buddy's own per-machine state
:> /etc/machine-id                        # so clones get their own id
rm -f /etc/ssh/ssh_host_*                 # the bootstrap runs `ssh-keygen -A`; otherwise clones share host keys
```

The credential is read from **stdin**, never from the command line, so it stays out of `ps` and shell history.
Shut the container down and convert it to a template (Proxmox: *More → Convert to template*).

## What happens on a clone's first boot

`ssh-buddy-bootstrap.service` (`After=network-online.target`, skipped if `/var/lib/ssh-buddy-agent/bootstrap-complete` exists). It is `Type=exec`,
so its start job finishes as soon as the script is running: **it never delays boot**. Other services start normally while it retries in the background.

1. retries `GET /api/agent/manifest.txt` for up to ~150 s (the network being "online" does not mean the server answers);
2. picks the line for this CPU (`x86_64` → `linux-amd64`, `aarch64` → `linux-arm64`), checks the manifest fields;
3. downloads the binary (size-capped), verifies **size and SHA-256** against the manifest, runs `ssh-buddy-agent version`, then
   installs it with an atomic rename. Any failure keeps the previously installed binary;
4. generates missing SSH host keys, then `ssh-buddy-agent install`: writes the sshd drop-in, runs `sshd -t`, reads the **effective**
   `AuthorizedKeysFile` with `sshd -T` and requires both `.ssh/authorized_keys` and `/etc/ssh/authorized_keys.d/%u-managed`
   (an overriding setting is an installation failure, not a warning), writes the systemd units, reloads/starts `ssh`, and
   **rolls everything back** if any step fails (restoring a previous drop-in exactly, or removing it if there was none);
5. runs the first sync + registration through `systemctl start ssh-buddy-agent.service` (same environment as the periodic runs);
6. only if that fully succeeded (unit succeeded, machine credential saved, first sync recorded) enables `ssh-buddy-agent.timer`
   (`interval`, default 5 min, ± up to 30 s random delay) and writes the completion marker.

On failure the script exits non-zero and systemd starts it again after 60 s (`Restart=on-failure`), indefinitely, until it succeeds. Each attempt
retries the API itself for about 150 s first. `systemctl status ssh-buddy-bootstrap` and `journalctl -u ssh-buddy-bootstrap` show progress.

Re-running is safe: it re-verifies the binary hash, re-applies `install`, and re-syncs.

## When a container is rebuilt

A rebuilt container with the same hostname is **refused** (`409`) and keeps syncing keys. In the UI it shows as
*Re-enrollment requested* with its address. Click **Permit re-enrollment**; its next bootstrap retry (≤ 60 s) enrolls, the old
credential stops working, and the permit is consumed.

The same applies to a machine that is still running after an administrator removed it: its agent notices the rejected credential,
asks to enroll on every run (which is what makes the request visible in the UI) and, once you click Permit, replaces its credential by
itself on its next run. Nothing has to be done on the machine. The permit is the only thing that makes the server say yes: it is single-use,
expires after `Machines__ReenrollPermitMinutes`, and whichever installation enrolls first consumes it, so power off or destroy the old
container before permitting its replacement.

## Not covered here

Network-online behaviour on Proxmox LXC (ifupdown vs systemd-networkd wait-online), Proxmox hostname/`/etc/hosts` generation, and
unprivileged-LXC sandboxing limits were not verified on a real Proxmox host; see the verification notes in the README.
