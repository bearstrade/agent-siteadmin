#!/usr/bin/env bash
set -eu

PREFIX=${SITEADMIN_INSTALL_DIR:-/opt/siteadmin}
STATE=${SITEADMIN_STATE_DIR:-/var/lib/siteadmin}
MODE=systemd
MODULE=monitor
PAIR=""
CHECK_ONLY=0
while [[ $# -gt 0 ]]; do
	case "$1" in
		--pair) PAIR="${2:-}"; shift 2 ;;
		--docker) MODE=docker; shift ;;
		--systemd) MODE=systemd; shift ;;
		--module) MODULE="${2:-}"; shift 2 ;;
		--check) CHECK_ONLY=1; shift ;;
		*) echo "Ошибка: неизвестный аргумент: $1" >&2; exit 2 ;;
	esac
done
if [[ "$MODULE" != monitor && "$MODULE" != serverctl && "$MODULE" != both ]]; then
	echo "Ошибка: --module должен быть monitor, serverctl или both." >&2
	exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then echo "Ошибка: требуется Python 3.10+. Установите python3." >&2; exit 2; fi
PYTHON=$(command -v python3)
if ! "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)'; then echo "Ошибка: нужен Python 3.10 или новее." >&2; exit 2; fi

# ── Пред-установка: системные зависимости (Debian/Ubuntu) ─────────────
# На свежих серверах python3-venv (ensurepip) и curl часто не стоят —
# ставим автоматически, чтобы установка проходила без ручных шагов.
APT_UPDATED=0
run_apt() {
	if [[ "$(id -u)" == 0 ]]; then
		"$@"
	elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
		sudo "$@"
	else
		echo "Ошибка: для установки пакетов нужен root или sudo." >&2
		exit 2
	fi
}
apt_install() {
	if [[ "$APT_UPDATED" == 0 ]]; then
		run_apt apt-get update -qq
		APT_UPDATED=1
	fi
	run_apt apt-get install -y --no-install-recommends "$@"
}
ensure_curl() {
	if command -v curl >/dev/null 2>&1; then return 0; fi
	if command -v apt-get >/dev/null 2>&1; then
		echo "Устанавливаю curl (нужен для скачивания исходников)..."
		apt_install curl
		return 0
	fi
	echo "Ошибка: отсутствует curl." >&2
	exit 2
}
ensure_ensurepip() {
	if "$PYTHON" -c 'import ensurepip' >/dev/null 2>&1; then return 0; fi
	if command -v apt-get >/dev/null 2>&1; then
		echo "Устанавливаю python3-venv (нужен для создания venv)..."
		apt_install python3-venv
		if ! "$PYTHON" -c 'import ensurepip' >/dev/null 2>&1; then
			echo "Ошибка: python3-venv установлен, но ensurepip всё ещё недоступен." >&2
			exit 2
		fi
		return 0
	fi
	echo "Ошибка: отсутствует ensurepip (python3-venv). Установите: apt install python3-venv" >&2
	exit 2
}
if [[ "$MODE" == docker ]]; then
	command -v docker >/dev/null 2>&1 || { echo "Ошибка: требуется docker." >&2; exit 2; }
	if [[ "$MODULE" == both ]]; then echo "Ошибка: для обоих модулей используйте --systemd." >&2; exit 2; fi
elif ! command -v systemctl >/dev/null 2>&1; then
	echo "Ошибка: требуется systemd (Ubuntu/Debian/RHEL/Alma)." >&2
	exit 2
fi
if [[ "$CHECK_ONLY" == 1 ]]; then
	if [[ "$MODULE" == serverctl || "$MODULE" == both ]] && [[ "$(id -u)" != 0 ]]; then
		echo "Ошибка: установка serverctl требует root или sudo." >&2
		exit 2
	fi
	echo "Проверка установщика пройдена: $MODE, module=$MODULE"
	exit 0
fi
if [[ -z "$PAIR" ]]; then read -r -p "Введите pairing-код: " PAIR; fi
if [[ -z "$PAIR" ]]; then echo "Ошибка: pairing-код не задан" >&2; exit 2; fi
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
if [[ ! -d "$SCRIPT_DIR/siteadmin" && -n "${SITEADMIN_AGENT_SOURCE_BASE:-}" ]]; then
	ensure_curl
	SOURCE_DIR=$(mktemp -d)
	trap 'rm -rf "$SOURCE_DIR"' EXIT
	mkdir -p "$SOURCE_DIR/siteadmin"
	for FILE in pyproject.toml Dockerfile siteadmin/__init__.py siteadmin/config.py siteadmin/state.py siteadmin/pairing.py siteadmin/channel.py siteadmin/system_profile.py siteadmin/security_scan.py siteadmin/telemetry.py siteadmin/events.py siteadmin/collector.py siteadmin/api.py siteadmin/setup.py siteadmin/update.py siteadmin/gateway.py siteadmin/uninstall.py siteadmin/__main__.py; do
		mkdir -p "$SOURCE_DIR/$(dirname "$FILE")"
		curl -fsSL "$SITEADMIN_AGENT_SOURCE_BASE/$FILE" -o "$SOURCE_DIR/$FILE"
	done
	SCRIPT_DIR="$SOURCE_DIR"
fi
if [[ ! -d "$SCRIPT_DIR/siteadmin" ]]; then echo "Ошибка: исходники агента недоступны." >&2; exit 2; fi
if [[ "$MODE" == docker ]]; then
	IMAGE=${SITEADMIN_DOCKER_IMAGE:-uhive/siteadmin-agent:local}
	CONTAINER=${SITEADMIN_DOCKER_CONTAINER:-siteadmin}
	DOCKER_VOLUME=siteadmin-state
	DOCKER_STATE_DIR=/var/lib/siteadmin
	if [[ "$MODULE" == serverctl ]]; then
		DOCKER_VOLUME=serverctl-state
		DOCKER_STATE_DIR=/var/lib/serverctl
		CONTAINER=${SITEADMIN_DOCKER_CONTAINER:-serverctl}
	fi
	if docker ps -a --format '{{.Names}}' | grep -Fxq "$CONTAINER"; then
		echo "Ошибка: контейнер $CONTAINER уже существует." >&2
		exit 2
	fi
	docker build -t "$IMAGE" "$SCRIPT_DIR"
	docker volume inspect "$DOCKER_VOLUME" >/dev/null 2>&1 || docker volume create "$DOCKER_VOLUME" >/dev/null
	docker run --rm --name "${CONTAINER}-pair" -v "$DOCKER_VOLUME:$DOCKER_STATE_DIR" \
		-e SITEADMIN_ENDPOINT="${SITEADMIN_ENDPOINT:-}" -e SITEADMIN_UPDATE_URL="${SITEADMIN_UPDATE_URL:-}" \
		-e SITEADMIN_MODULE="$MODULE" -e SITEADMIN_STATE_DIR="$DOCKER_STATE_DIR" \
		"$IMAGE" pair "$PAIR"
	docker run -d --name "$CONTAINER" --restart unless-stopped -v "$DOCKER_VOLUME:$DOCKER_STATE_DIR" \
		-e SITEADMIN_ENDPOINT="${SITEADMIN_ENDPOINT:-}" -e SITEADMIN_UPDATE_URL="${SITEADMIN_UPDATE_URL:-}" \
		-e SITEADMIN_DOMAINS="${SITEADMIN_DOMAINS:-}" -e SITEADMIN_MODULE="$MODULE" \
		-e SITEADMIN_STATE_DIR="$DOCKER_STATE_DIR" "$IMAGE" run >/dev/null
	echo "Установка Docker завершена. Проверка: docker logs $CONTAINER"
	exit 0
fi
install_systemd_module() {
	local module="$1" prefix="$2" state="$3" service="$4" cli="$5"
	if [[ "$module" == serverctl && "$(id -u)" != 0 ]]; then
		echo "Ошибка: установка serverctl требует root или sudo." >&2
		exit 2
	fi
	ensure_ensurepip
	mkdir -p "$prefix" "$state" "/etc/$module"
	cp -R "$SCRIPT_DIR/siteadmin" "$prefix/"
	cp "$SCRIPT_DIR/pyproject.toml" "$prefix/"
	# venv пересоздаём начисто: после неудачной попытки он может быть битым
	[[ -d "$prefix/venv" ]] && rm -rf "$prefix/venv"
	echo "Создаю виртуальное окружение ($prefix/venv)..."
	python3 -m venv "$prefix/venv"
	if [[ ! -x "$prefix/venv/bin/pip" ]]; then
		echo "Ошибка: в venv не появился pip (проблема с ensurepip)." >&2
		exit 2
	fi
	echo "Устанавливаю зависимости (cryptography)..."
	"$prefix/venv/bin/pip" install --no-cache-dir "cryptography>=42,<46"
	cat > "/etc/systemd/system/$service.service" <<UNIT
[Unit]
Description=uHive $module Agent
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
Environment=SITEADMIN_MODULE=$module
Environment=SITEADMIN_STATE_DIR=$state
Environment=SITEADMIN_INSTALL_DIR=$prefix
EnvironmentFile=-/etc/$module/$module.env
ExecStart=$prefix/venv/bin/python -m siteadmin run
WorkingDirectory=$prefix
Restart=always
RestartSec=10
NoNewPrivileges=true
ProtectHome=read-only
[Install]
WantedBy=multi-user.target
UNIT
printf 'SITEADMIN_ENDPOINT=%s\nSITEADMIN_UPDATE_URL=%s\nSITEADMIN_DOMAINS=%s\n' "${SITEADMIN_ENDPOINT:-https://hub.uhive.ai}" "${SITEADMIN_UPDATE_URL:-}" "${SITEADMIN_DOMAINS:-}" > "/etc/$module/$module.env"
chmod 600 "/etc/$module/$module.env"
cat > "/usr/local/bin/$cli" <<CLI
#!/usr/bin/env bash
exec $prefix/venv/bin/python -m siteadmin "\$@"
CLI
chmod 755 "/usr/local/bin/$cli"
# pair выполняется из каталога модуля: `python -m siteadmin` ищет пакет в cwd
(
	cd "$prefix"
	"$prefix/venv/bin/python" -m siteadmin pair "$PAIR"
)
}

if [[ "$MODULE" == monitor || "$MODULE" == both ]]; then
	install_systemd_module monitor "$PREFIX" "$STATE" siteadmin siteadmin
fi
if [[ "$MODULE" == serverctl || "$MODULE" == both ]]; then
	install_systemd_module serverctl /opt/serverctl /var/lib/serverctl serverctl serverctl
fi
systemctl daemon-reload
if [[ "$MODULE" == monitor || "$MODULE" == both ]]; then systemctl enable --now siteadmin.service; fi
if [[ "$MODULE" == serverctl || "$MODULE" == both ]]; then systemctl enable --now serverctl.service; fi
echo "Установка завершена: module=$MODULE. Проверка: systemctl status siteadmin/serverctl"
echo "Документация: https://hub.uhive.ai/docs/site-admin"
