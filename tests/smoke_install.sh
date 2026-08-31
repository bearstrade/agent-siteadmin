#!/usr/bin/env bash
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"
printf '#!/usr/bin/env bash\nexit 0\n' > "$TMP/bin/systemctl"
printf '#!/usr/bin/env bash\nexit 0\n' > "$TMP/bin/docker"
chmod 755 "$TMP/bin/systemctl" "$TMP/bin/docker"
PATH="$TMP/bin:$PATH" bash "$ROOT/install.sh" --check --systemd
PATH="$TMP/bin:$PATH" bash "$ROOT/install.sh" --check --docker
printf 'installer smoke ok\n'
