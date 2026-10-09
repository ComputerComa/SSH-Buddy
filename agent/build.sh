#!/usr/bin/env bash
# Build the static ssh-buddy-agent binaries for Linux amd64 and arm64 into dist/<version>/.
# Usage: ./build.sh [version]        (default: contents of ./VERSION)
#
# The output directory is exactly what SSH Buddy serves: copy dist/<version>/ into the server's
# Agent:ReleaseDirectory (see docs/agent-release.md). Builds are reproducible: same source, same Go
# toolchain, same version string => byte-identical binaries (run `./build.sh --verify` to prove it).
set -euo pipefail
cd "$(dirname "$0")"

# go.mod pins the toolchain (go1.26.x). Builds must use it, not whatever Go the machine happens to have:
# older standard libraries contain published crypto/tls, net/http and x509 vulnerabilities.
export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"

verify=0
if [ "${1:-}" = "--verify" ]; then verify=1; shift; fi
version="${1:-$(tr -d '[:space:]' < VERSION)}"
case "$version" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "version must look like 1.2.3 or 1.2.3-rc1, got '$version'" >&2; exit 2 ;;
esac

out="dist/$version"

build_all() {
  local dest="$1"
  rm -rf "$dest"; mkdir -p "$dest"
  for arch in amd64 arm64; do
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOFLAGS=-mod=readonly \
      go build -trimpath -buildvcs=false \
        -ldflags "-s -w -buildid= -X main.version=$version" \
        -o "$dest/ssh-buddy-agent-linux-$arch" .
  done
  ( cd "$dest" && sha256sum ssh-buddy-agent-linux-amd64 ssh-buddy-agent-linux-arm64 > SHA256SUMS )
}

go test -count=1 ./...
if command -v govulncheck >/dev/null 2>&1 || [ -x "$HOME/go/bin/govulncheck" ]; then
  PATH="$PATH:$HOME/go/bin" govulncheck ./...
else
  echo "note: govulncheck not installed; skipping the vulnerability scan (go install golang.org/x/vuln/cmd/govulncheck@latest)" >&2
fi
build_all "$out"
echo "built $out:"; cat "$out/SHA256SUMS"

if [ "$verify" = 1 ]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  build_all "$tmp/second"
  if cmp -s "$out/SHA256SUMS" "$tmp/second/SHA256SUMS"; then
    echo "reproducible: a second build produced identical checksums"
  else
    echo "NOT reproducible: checksums differ" >&2; diff "$out/SHA256SUMS" "$tmp/second/SHA256SUMS" >&2 || true; exit 1
  fi
fi
