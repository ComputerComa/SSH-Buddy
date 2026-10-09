# Integration run

`integration/run.sh` exercises the whole stack the way it is deployed, in Docker. It is slow (about 10 minutes, mostly
systemd timers) and is not part of `dotnet test`.

```bash
integration/run.sh            # runs everything, prints PASS/FAIL lines and a summary, cleans up
KEEP=1 integration/run.sh     # leave the sb-* containers, network `sbnet` and volume `sb-data` for inspection
```

Requirements: Docker with cgroup v2 and permission to run `--privileged` containers (they run systemd as PID 1), the .NET SDK,
Go, and `openssl`. It pulls `mcr.microsoft.com/playwright` (about 3.5 GB), `nginx:stable-alpine` and `curlimages/curl` on first use.
It creates only `sb-*` containers/images, the network `sbnet` (172.30.0.0/24) and the volume `sb-data`, and removes them at the end.

```
Playwright/Chromium ──┐
                      ├──► nginx (TLS from a throwaway CA, X-Forwarded-*) ──► SshBuddy.Web (Production, published, self-contained)
Debian 13 + systemd ──┘                                                       ▲ agent releases built by agent/build.sh
 clone of the "template" image (bootstrap -> agent -> timer)
```

What it covers: see the README's *Verification status*. The browser scripts are `ui/ui1.mjs` (login, keys, template credential),
`ui2.mjs` (Machines page, removal, re-enrollment request and permit; run in phases a/b/c), `ui3.mjs` (add/revoke a key) and
`ui4.mjs` (stale/healthy badge).

Notes:

* The *browser* ignores certificate errors (Chromium cannot see the container's CA store). The agent and the bootstrap do **not**: they verify TLS against the CA installed in the template.
* Docker is not LXC. Proxmox-specific behaviour (network-online ordering, hostname/hosts generation, unprivileged restrictions) is not exercised.
* The `systemd-modules-load.service` failure inside the containers is a container artefact.
