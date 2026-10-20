# Building and publishing the Go agent

The agent (`agent/`) is a single static binary with no runtime dependencies. Linux **amd64** and **arm64** are built.
The target machines never need Go; only the machine that builds releases does.

## Toolchain (pinned)

`agent/go.mod` pins **Go 1.26.9** (`toolchain go1.26.9`) and `golang.org/x/crypto v0.58.0`.
This is deliberate: `govulncheck` reports dozens of published `crypto/tls`, `net/http`, `crypto/x509` and `os/exec`
vulnerabilities in older Go standard libraries (it flagged 35 in Go 1.24.4, the version that happened to be installed
when this was written, plus one in `x/crypto` v0.40.0), and the shipped binary embeds the standard library it was built with.
With the default `GOTOOLCHAIN=auto`, any recent `go` command downloads and uses the pinned toolchain by itself.
Raise the pin (and re-run the scan) when new Go security releases appear.

## Build

```bash
cd agent
./build.sh 1.2.0      # explicit version
./build.sh            # 0.0.0-dev
./build.sh --verify   # builds twice and fails unless the checksums are identical
```

Releases do not run this by hand: the version comes from the git tag, and the top-level `build.sh` (run by the
GitHub workflow, see the README's *Releases*) calls `agent/build.sh <version>` and puts the result into the server bundle.

`build.sh` runs the tests, runs `govulncheck` if it is installed
(`go install golang.org/x/vuln/cmd/govulncheck@latest`), then writes

```
agent/dist/<version>/ssh-buddy-agent-linux-amd64
agent/dist/<version>/ssh-buddy-agent-linux-arm64
agent/dist/<version>/SHA256SUMS
```

Flags: `CGO_ENABLED=0 -trimpath -buildvcs=false -ldflags "-s -w -buildid= -X main.version=<version>"`.
**Reproducibility** was checked: two builds, and a build from a copy of the sources in a different directory, produced
byte-identical binaries (same toolchain, same version string). Different Go versions produce different bytes.

Test commands: `cd agent && go test -race ./...` (the Go suite uses a real TLS server, atomic-write and lock checks).

## Publish

SSH Buddy serves whatever it finds under `Agent:ReleaseDirectory` (default `App_Data/agent`, in production
`Agent__ReleaseDirectory`). The server bundle carries `agent/<version>/`, and its `install.sh` copies it there, so installing
or upgrading the server publishes the agent of the same version. To publish an agent build by hand, copy the version
directory there; no restart is needed.

```bash
V=1.2.0; rsync -a "agent/dist/$V/" "root@keys-lxc:/var/lib/ssh-buddy/agent/$V/"
```

Rules the server applies:

* Only **complete** versions are served: both binaries present, and the `SHA256SUMS` written by the build must match the
  hash the server computes from the files. A half-copied or tampered release is simply invisible.
* The highest complete semantic version wins (a release outranks its own prereleases). Pin one with `Agent__Version=1.2.0`.
* Version and platform in download URLs are whitelisted; path tricks return 404.

Endpoints (all public, like the key list, because they contain no secrets):

| Endpoint | Content |
|---|---|
| `GET /api/agent/manifest` | JSON: `version` and, per binary, `os`, `arch`, `platform`, `size`, `sha256`, `path` |
| `GET /api/agent/manifest.txt` | the same data, one line per binary: `version platform size sha256 path` (for the shell bootstrap, which has no JSON parser) |
| `GET /api/agent/download/{version}/{platform}` | the binary (`platform` = `linux-amd64` or `linux-arm64`) |

> **A checksum is not a signature.** The manifest and the binary come from the same server, so the SHA-256 protects against
> corruption and partial uploads, not against a compromised server or a man in the middle who also holds a valid
> certificate. The real trust anchor is TLS to your SSH Buddy host, verified against the CA you baked into the template.
> Signing releases with an offline key is a possible later improvement.

## Upgrades

First-boot download/install is implemented. Automatic ongoing upgrades are not: to roll a new agent onto existing machines,
publish the new version (upgrading the server does) and run the bootstrap again on them, which replaces the binary atomically
only after the new one downloads, matches its checksum and runs:

```bash
rm /var/lib/ssh-buddy-agent/bootstrap-complete && systemctl restart ssh-buddy-bootstrap
# from the Proxmox host:
for ct in 101 102 103; do pct exec "$ct" -- sh -c 'rm -f /var/lib/ssh-buddy-agent/bootstrap-complete && systemctl restart ssh-buddy-bootstrap'; done
```

Use `restart`, not `start`: the unit is `RemainAfterExit=yes`, so after its first-boot run it stays "active (exited)" and
`systemctl start` does nothing.
