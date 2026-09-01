#!/usr/bin/env bash
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
"$ROOT/install.sh" --check --systemd --module monitor
if [[ "$(id -u)" == 0 ]]; then
	"$ROOT/install.sh" --check --systemd --module serverctl
	"$ROOT/install.sh" --check --systemd --module both
else
	echo "serverctl smoke пропущен: нужен root/sudo для проверки установки." >&2
fi
python3 -m pytest -q "$ROOT/tests/test_serverctl.py"