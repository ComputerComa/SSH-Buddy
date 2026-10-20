#!/usr/bin/env bash
# Builds the release bundles into dist/:
#   dist/ssh-buddy-server-linux-x64.tar.gz   the server, its installer, and the agent release it serves
#   dist/ssh-buddy-template.tar.gz           the first-boot bootstrap for an LXC template (DAB or hand-made)
#
#   ./build.sh                 version 0.0.0-dev
#   VERSION=1.2.0 ./build.sh   stamp a version into the server and the agent (CI sets this from the release tag)
#
# Needs the .NET 10 SDK and Go (any recent go; agent/go.mod pins the toolchain it downloads).
# Put a filled-in deploy/ssh-buddy.env (gitignored) next to the example to ship it in the server bundle.
set -euo pipefail
cd "$(dirname "$0")"

version="${VERSION:-0.0.0-dev}"
server=ssh-buddy-server-linux-x64
template=ssh-buddy-template

rm -rf "dist/$server" "dist/$server.tar.gz" "dist/$template" "dist/$template.tar.gz"

# The agent first: agent/build.sh runs its tests and govulncheck, and refuses a malformed version.
agent/build.sh "$version"

dotnet publish src/SshBuddy.Web -c Release -r linux-x64 --self-contained -o "dist/$server/app" --nologo "-p:Version=$version"
mkdir -p "dist/$server/agent"
cp -R "agent/dist/$version" "dist/$server/agent/$version"
install -m 0755 deploy/install.sh deploy/ssh-buddy deploy/backup.sh "dist/$server/"
cp deploy/ssh-buddy.service deploy/ssh-buddy.env.example deploy/nginx.conf.example "dist/$server/"
printf '%s\n' "$version" > "dist/$server/VERSION"
if [[ -f deploy/ssh-buddy.env ]]; then
    install -m 0600 deploy/ssh-buddy.env "dist/$server/"
    echo "note: server bundle includes deploy/ssh-buddy.env"
fi

mkdir -p "dist/$template"
install -m 0755 template/install-into-template.sh template/prepare-template.sh template/ssh-buddy-bootstrap "dist/$template/"
cp template/ssh-buddy-bootstrap.service template/agent.conf.example "dist/$template/"

tar -C dist -czf "dist/$server.tar.gz" "$server"
tar -C dist -czf "dist/$template.tar.gz" "$template"
echo "built dist/$server.tar.gz and dist/$template.tar.gz ($version)"
