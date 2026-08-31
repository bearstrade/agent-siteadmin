#!/usr/bin/env bash
set -eu

PREFIX=${SITEADMIN_INSTALL_DIR:-/opt/siteadmin}
STATE=${SITEADMIN_STATE_DIR:-/var/lib/siteadmin}
MODE=systemd
PAIR=""
CHECK_ONLY=0
while [[ $# -gt 0 ]]; do
	case "$1" in
		--pair) PAIR="${2:-}"; shift 2 ;;
		--docker) MODE=docker; shift ;;
		--systemd) MODE=systemd; shift ;;
		--check) CHECK_ONLY=1; shift ;;
		*) echo "Ошибка: неизвестный аргумент: $1" >&2; exit 2 ;;
	esac
done
if ! command -v python3 >/dev/null 2>&1; then echo "Ошибка: требуется Python 3.10+. Установите python3." >&2; exit 2; fi
PYTHON=$(command -v python3)
if ! "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)'; then echo "Ошибка: нужен Python 3.10 или новее." >&2; exit 2; fi
if [[ "$MODE" == docker ]]; then
	command -v docker >/dev/null 2>&1 || { echo "Ошибка: требуется docker." >&2; exit 2; }
elif ! command -v systemctl >/dev/null 2>&1; then
	echo "Ошибка: требуется systemd (Ubuntu/Debian/RHEL/Alma)." >&2
	exit 2
fi
if [[ "$CHECK_ONLY" == 1 ]]; then
	echo "Проверка установщика пройдена: $MODE"
	exit 0
fi
if [[ -z "$PAIR" ]]; then read -r -p "Введите pairing-код: " PAIR; fi
if [[ -z "$PAIR" ]]; then echo "Ошибка: pairing-код не задан" >&2; exit 2; fi
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
if [[ ! -d "$SCRIPT_DIR/siteadmin" && -n "${SITEADMIN_AGENT_SOURCE_BASE:-}" ]]; then
	SOURCE_DIR=$(mktemp -d)
	trap 'rm -rf "$SOURCE_DIR"' EXIT
	mkdir -p "$SOURCE_DIR/siteadmin"
	for FILE in pyproject.toml Dockerfile siteadmin/__init__.py siteadmin/config.py siteadmin/state.py siteadmin/pairing.py siteadmin/channel.py siteadmin/system_profile.py siteadmin/security_scan.py siteadmin/telemetry.py siteadmin/events.py siteadmin/collector.py siteadmin/api.py siteadmin/setup.py siteadmin/update.py siteadmin/gateway.py siteadmin/__main__.py; do
		mkdir -p "$SOURCE_DIR/$(dirname "$FILE")"
		curl -fsSL "$SITEADMIN_AGENT_SOURCE_BASE/$FILE" -o "$SOURCE_DIR/$FILE"
	done
	SCRIPT_DIR="$SOURCE_DIR"
fi
if [[ ! -d "$SCRIPT_DIR/siteadmin" ]]; then echo "Ошибка: исходники агента недоступны." >&2; exit 2; fi
if [[ "$MODE" == docker ]]; then
	IMAGE=${SITEADMIN_DOCKER_IMAGE:-uhive/siteadmin-agent:local}
	CONTAINER=${SITEADMIN_DOCKER_CONTAINER:-siteadmin}
	if docker ps -a --format '{{.Names}}' | grep -Fxq "$CONTAINER"; then
		echo "Ошибка: контейнер $CONTAINER уже существует." >&2
		exit 2
	fi
	docker build -t "$IMAGE" "$SCRIPT_DIR"
	docker volume inspect siteadmin-state >/dev/null 2>&1 || docker volume create siteadmin-state >/dev/null
	docker run --rm --name "${CONTAINER}-pair" -v siteadmin-state:/var/lib/siteadmin \
		-e SITEADMIN_ENDPOINT="${SITEADMIN_ENDPOINT:-}" -e SITEADMIN_UPDATE_URL="${SITEADMIN_UPDATE_URL:-}" \
		"$IMAGE" pair "$PAIR"
	docker run -d --name "$CONTAINER" --restart unless-stopped -v siteadmin-state:/var/lib/siteadmin \
		-e SITEADMIN_ENDPOINT="${SITEADMIN_ENDPOINT:-}" -e SITEADMIN_UPDATE_URL="${SITEADMIN_UPDATE_URL:-}" \
		-e SITEADMIN_DOMAINS="${SITEADMIN_DOMAINS:-}" "$IMAGE" run >/dev/null
	echo "Установка Docker завершена. Проверка: docker logs $CONTAINER"
	exit 0
fi
if [[ ! -d "$PREFIX" ]]; then mkdir -p "$PREFIX"; fi
mkdir -p "$STATE"
cp -R "$SCRIPT_DIR/siteadmin" "$PREFIX/"
cp "$SCRIPT_DIR/pyproject.toml" "$PREFIX/"
python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --no-cache-dir "cryptography>=42,<46"
cat > /etc/systemd/system/siteadmin.service <<UNIT
[Unit]
Description=uHive Site Admin Agent
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
Environment=SITEADMIN_STATE_DIR=$STATE
Environment=SITEADMIN_INSTALL_DIR=$PREFIX
EnvironmentFile=-/etc/siteadmin/siteadmin.env
ExecStart=$PREFIX/venv/bin/python -m siteadmin run
WorkingDirectory=$PREFIX
Restart=always
RestartSec=10
NoNewPrivileges=true
ProtectHome=read-only
[Install]
WantedBy=multi-user.target
UNIT
mkdir -p /etc/siteadmin
printf 'SITEADMIN_ENDPOINT=%s\nSITEADMIN_UPDATE_URL=%s\nSITEADMIN_DOMAINS=%s\n' "${SITEADMIN_ENDPOINT:-https://hub.uhive.ai}" "${SITEADMIN_UPDATE_URL:-}" "${SITEADMIN_DOMAINS:-}" > /etc/siteadmin/siteadmin.env
chmod 600 /etc/siteadmin/siteadmin.env
cat > /usr/local/bin/siteadmin <<CLI
#!/usr/bin/env bash
exec $PREFIX/venv/bin/python -m siteadmin "\$@"
CLI
chmod 755 /usr/local/bin/siteadmin
"$PREFIX/venv/bin/python" -m siteadmin pair "$PAIR"
systemctl daemon-reload
systemctl enable --now siteadmin.service
echo "Установка завершена. Проверка: systemctl status siteadmin; siteadmin status"
echo "Документация: https://hub.uhive.ai/docs/site-admin"
