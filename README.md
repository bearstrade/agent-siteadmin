# Site Admin Agent

Linux-агент для раздела «Сайт-админ» uHive. Поддерживает Ubuntu/Debian и
RHEL/Alma с Python 3.10+. Проект рассчитан на открытое использование и не
требует входящего порта на сервере пользователя.

## Как это работает

Агент собирает обработанный профиль, findings и агрегированную телеметрию,
затем отправляет их исходящими HTTPS-запросами. Команды приходят через
long-poll; локальное состояние и outbox переживают временный обрыв сети.
В безопасном режиме доступны только именованные операции L0-L2. L3 setup
включается владельцем Hive на ограниченное время и защищён blocklist.

Поддерживаемые обновления проверяют Ed25519-подпись манифеста и SHA-256
архива. Перед заменой пакет компилируется, предыдущая версия сохраняется для
отката, pairing и каталог состояния не заменяются.

## Установка

```sh
curl -fsSL https://hub.uhive.ai/agent-siteadmin/install.sh | sudo bash -- --pair CODE
```

Для dev задайте `SITEADMIN_ENDPOINT` перед запуском установщика. Для событий об
истечении TLS-сертификата и недоступности сайта изнутри задайте адреса через
`SITEADMIN_DOMAINS=example.com,https://admin.example.com`. Агент сам создаёт
venv, systemd unit и локальное состояние в `/var/lib/siteadmin`.

Установщик поддерживает явный выбор способа запуска:

```sh
curl -fsSL https://hub.uhive.ai/agent-siteadmin/install.sh | sudo bash -- --systemd --pair CODE
curl -fsSL https://hub.uhive.ai/agent-siteadmin/install.sh | sudo bash -- --docker --pair CODE
```

Для предварительной проверки окружения без установки: `bash install.sh
--check --systemd` или `bash install.sh --check --docker`.

Выбор модулей выполняется явно: `--module monitor` (только телеметрия),
`--module serverctl` (только постоянный доступ бота) или `--module both`.
Для `serverctl` требуется запуск от root/sudo; он использует отдельные
`/opt/serverctl`, `/var/lib/serverctl`, `serverctl.service` и CLI `serverctl`.
Удаление через `serverctl uninstall` не затрагивает `siteadmin`.

## Docker

```sh
docker build -t siteadmin-agent .
docker volume create siteadmin-state
docker run -d --name siteadmin --restart unless-stopped \
	-v siteadmin-state:/var/lib/siteadmin \
	-e SITEADMIN_ENDPOINT=https://hub.uhive.ai \
	siteadmin-agent run
```

Перед `run` один раз выполните pairing с тем же volume:
`docker run --rm -v siteadmin-state:/var/lib/siteadmin siteadmin-agent pair CODE`.
Готовый локальный вариант находится в `docker-compose.yml`.

## Обновление

```sh
siteadmin update --check
siteadmin update
```

`SITEADMIN_UPDATE_URL` указывает на JSON-манифест релиза. Агент принимает
только HTTPS, кроме специально разрешённого localhost HTTP в тестах.

## Безопасность

Агент не открывает внешний порт: связь с сервисом только исходящими HTTPS-запросами и long-poll. Профиль, findings, телеметрия и события агрегируются локально; секреты и сырые логи не отправляются. Состояние и outbox имеют права 0600/0700. Локальный API слушает только `127.0.0.1`.

Проверка: `systemctl status siteadmin`, `siteadmin status`, `siteadmin scan`, `journalctl -u siteadmin.service`.

## Разработка

```sh
python3 -m pip install -e '.[test,lint]'
python3 -m pytest -q
ruff check siteadmin tests
bash tests/smoke_install.sh
```

Правила сообщения об уязвимостях описаны в [`SECURITY.md`](SECURITY.md).
