#!/usr/bin/env bash
set -euo pipefail
workspace=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
repo=$(cd -- "$workspace/.." && pwd)
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || {
    echo 'Este paquete requiere un host Linux x86_64.' >&2; exit 1;
}
cd "$workspace"
version=$(cargo pkgid -p punishell-server --locked | sed 's/.*@//')
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.+-]+)?$ ]] || exit 1
if [[ -n ${RELEASE_TAG:-} && $RELEASE_TAG != "v$version" ]]; then
    echo 'El tag debe coincidir con la versión del workspace.' >&2; exit 1
fi
cargo build --release --target x86_64-unknown-linux-gnu -p punishell-server --locked
output="$repo/dist"
mkdir -p "$output"
name="punishell-server-$version-linux-x86_64"
archive="$output/$name.tar.gz"
[[ ! -e $archive && ! -e $archive.sha256 ]] || { echo "Ya existe $archive" >&2; exit 1; }
stage=$(mktemp -d "$output/.linux-package.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT
mkdir "$stage/$name"
install -m 0755 "target/x86_64-unknown-linux-gnu/release/punishell-server" "$stage/$name/punishell-server"
install -m 0755 "$repo/despliegue_ps1/install_server_linux.sh" "$stage/$name/"
install -m 0644 "$repo/despliegue_ps1/punishell-server.service" "$stage/$name/"
install -m 0644 "$workspace/README.md" "$stage/$name/README.md"
install -m 0644 "$workspace/docs/RELEASES.md" "$stage/$name/RELEASES.md"
"$stage/$name/punishell-server" --version
tar -C "$stage" -czf "$archive" "$name"
cd "$output"
sha256sum "$name.tar.gz" > "$name.tar.gz.sha256"
echo "Paquete: $archive"
