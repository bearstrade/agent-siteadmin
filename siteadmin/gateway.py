"""Именованный шлюз операций безопасного режима агента."""

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import time
from pathlib import Path

from .security_scan import _listeners
from .setup import SETUP_CATALOG, SetupError, setup_apply, setup_expire, setup_plan, setup_start, setup_status, setup_stop
from .system_profile import collect as collect_profile
from .telemetry import _certificate_days, _domains


LEVELS = {"L0": 0, "L1": 1, "L2": 2}
CATALOG = {
    "status": ("L0", "Сводка системы и сервисов"),
    "disk": ("L0", "Точки монтирования и занятость"),
    "services": ("L0", "Статусы сервисов"),
    "ports": ("L0", "Слушающие порты"),
    "certs": ("L0", "Сроки TLS-сертификатов"),
    "logs_tail": ("L0", "Последние строки журнала сервиса"),
    "service_restart_graceful": ("L1", "Мягкий перезапуск сервиса"),
    "nginx_reload": ("L1", "Проверка и reload nginx"),
    "cache_clear": ("L1", "Очистка известных кэш-путей"),
    "tmp_clean": ("L1", "Очистка временных файлов агента"),
    "cert_renew_dry": ("L1", "Пробный certbot renew"),
    "service_restart": ("L2", "Принудительный перезапуск сервиса"),
    "service_stop": ("L2", "Остановка сервиса"),
    "config_apply": ("L2", "Замена конфигурации с backup"),
    "cache_clear_force": ("L2", "Принудительная очистка кэша"),
    "backup_cleanup": ("L2", "Удаление старых rollback backup"),
    "apt_update": ("L1", "Обновление индекса apt"),
    "dnf_update": ("L1", "Обновление индекса dnf"),
    "package_install": ("L2", "Установка пакетов с dry-run"),
    "package_remove": ("L2", "Удаление пакетов с dry-run"),
    "packages_installed": ("L0", "Список установленных пакетов"),
    "config_read": ("L0", "Чтение файла конфигурации по allowlist"),
    "db_list": ("L0", "Список баз данных"),
    "db_status": ("L0", "Статус MySQL/PostgreSQL"),
    "db_backup": ("L2", "Резервная копия базы данных"),
    "git_pull": ("L2", "Обновление git checkout с fast-forward"),
    "systemd_reload": ("L1", "Перечитать конфигурацию systemd"),
    "cert_renew": ("L1", "Продлить сертификаты certbot"),
    "shell": ("L2", "Команда shell в режиме serverctl"),
}
SERVERCTL_OPS = {
    "apt_update", "dnf_update", "package_install", "package_remove", "packages_installed",
    "config_read", "db_list", "db_status", "db_backup", "git_pull", "systemd_reload",
    "cert_renew", "shell",
}

SERVICES = {"nginx", "apache2", "httpd", "php-fpm", "docker", "fail2ban"}
CACHE_PATHS = {"nginx": Path("/var/cache/nginx"), "apache2": Path("/var/cache/apache2")}
CONFIG_ROOTS = (Path("/etc/nginx"), Path("/etc/apache2"), Path("/etc/httpd"))
CONFIG_READ_ROOTS = CONFIG_ROOTS + (Path("/etc/mysql"), Path("/etc/postgresql"), Path("/etc/systemd/system"))
REPO_ROOTS = (Path("/var/www"), Path("/srv/www"), Path("/opt"))
PACKAGE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9+_.:@-]{0,127}$")
DATABASE_RE = re.compile(r"^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,62}$")
SECRET_RE = re.compile(r"(?i)(password|passwd|token|secret|private[_ -]?key|credential|api[_ -]?key)(\s*[:=]\s*)[^\s,;]+")
DANGEROUS_SHELL = re.compile(
    r"(?ix)(?:\brm\s+(?:-[\w-]+\s+)*-rf\b|\bmkfs(?:\.[\w]+)?\b|\bdd\s+if=|"
    r"\bchmod\s+-R\s+/|\b(?:shutdown|reboot|halt)\b|\bsystemctl\s+(?:stop|disable|mask)\b)"
)


class OperationError(Exception):
    def __init__(self, code: str, message: str = ""):
        self.code = code
        self.message = message or code
        super().__init__(self.message)


def _masked(value: str) -> str:
    return SECRET_RE.sub(lambda match: match.group(1) + match.group(2) + "[redacted]", value)[:8000]


def _run(*args, timeout=20):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise OperationError("command_unavailable", str(exc)) from exc


def _service(params):
    name = str(params.get("service") or "").strip().lower()
    if name not in SERVICES:
        raise OperationError("invalid_service", "Сервис не входит в allowlist")
    return name


def _path_in_roots(value: str) -> Path:
    path = Path(str(value or "")).resolve()
    if any(path == root or root in path.parents for root in CONFIG_ROOTS):
        return path
    raise OperationError("invalid_config_path", "Путь конфигурации не входит в allowlist")


def _read_path_in_roots(value: str) -> Path:
    path = Path(str(value or "")).expanduser().resolve()
    if any(path == root or root in path.parents for root in CONFIG_READ_ROOTS):
        return path
    raise OperationError("invalid_config_path", "Путь конфигурации не входит в allowlist")


def _repo_path(value: str) -> Path:
    path = Path(str(value or "")).expanduser().resolve()
    if any(path == root or root in path.parents for root in REPO_ROOTS):
        return path
    raise OperationError("invalid_repo_path", "Репозиторий не входит в allowlist")


def _packages(value, *, field="packages"):
    values = value.get(field, value.get("package"))
    values = [values] if isinstance(values, str) else values
    if not isinstance(values, list) or not values or len(values) > 20:
        raise OperationError("invalid_package", "Нужен список из 1-20 пакетов")
    names = [str(item).strip() for item in values]
    if any(not PACKAGE_RE.fullmatch(item) for item in names):
        raise OperationError("invalid_package", "Имя пакета не прошло проверку")
    return names


def _database(value: str) -> str:
    name = str(value or "").strip()
    if not DATABASE_RE.fullmatch(name):
        raise OperationError("invalid_database", "Имя базы данных не прошло проверку")
    return name


class OperationGateway:
    def __init__(self, state):
        self.state = state
        self._requests = []
        self.rollback_dir = state.directory / "rollback"
        self.rollback_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.rollback_dir, 0o700)

    def catalog(self):
        result = {name: {"level": level, "description": description} for name, (level, description) in CATALOG.items()}
        result.update({name: {"level": "L3", "description": description} for name, description in SETUP_CATALOG.items()})
        return result

    def _rate_limit(self):
        now = time.monotonic()
        self._requests = [stamp for stamp in self._requests if now - stamp < 60]
        if len(self._requests) >= 30:
            raise OperationError("rate_limited", "Слишком много операций")
        self._requests.append(now)

    def _confirm(self, token):
        if not token:
            raise OperationError("confirm_required", "Для L2 нужна одноразовая confirm-токен")
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        values = self.state.read().get("gateway_confirmations", {})
        record = values.pop(digest, None)
        self.state.update(gateway_confirmations=values)
        if not record or float(record.get("expires", 0)) < time.time():
            raise OperationError("invalid_confirm_token", "Confirm-токен недействителен или истёк")

    def _new_confirmation(self):
        token = secrets.token_urlsafe(32)
        values = self.state.read().get("gateway_confirmations", {})
        values[hashlib.sha256(token.encode("utf-8")).hexdigest()] = {"expires": time.time() + 120}
        self.state.update(gateway_confirmations=values)
        return token

    def execute(self, op: str, params=None, *, dry_run=False, confirm_token=None, setup_session_id=None):
        self._rate_limit()
        params = params if isinstance(params, dict) else {}
        if op in SERVERCTL_OPS and self.state.read().get("module", "monitor") != "serverctl":
            return {"ok": False, "error": {"code": "unknown_operation", "message": "Операция не зарегистрирована"}}
        if op not in CATALOG and op not in SETUP_CATALOG:
            return {"ok": False, "error": {"code": "unknown_operation", "message": "Операция не зарегистрирована"}}
        level = CATALOG[op][0] if op in CATALOG else "L3"
        try:
            if level == "L3":
                mode = setup_status(self.state)
                if not mode.get("active") or setup_session_id is not None and int(mode.get("session_id", 0)) != int(setup_session_id):
                    raise SetupError("setup_required", "Setup mode не активен или сессия недействительна")
                plan = setup_plan(op, params, self.state)
            else:
                plan = self._plan(op, params)
            if op == "shell":
                state = self.state.read()
                if state.get("module", "monitor") != "serverctl":
                    raise OperationError("module_required", "Shell доступен только модулю serverctl")
                if not state.get("access_enabled", True):
                    raise OperationError("access_disabled", "Доступ serverctl отключён владельцем")
                if not state.get("shell_enabled", False):
                    raise OperationError("shell_disabled", "Shell-режим выключен владельцем")
                if os.geteuid() != 0:
                    raise OperationError("root_required", "serverctl требует root-привилегии")
            if dry_run:
                result = {"ok": True, "data": {"plan": plan}}
                if level == "L2":
                    result["confirm_token"] = self._new_confirmation()
                return result
            if level == "L2":
                self._confirm(confirm_token)
            if level == "L3":
                return setup_apply(op, params, plan, self.state)
            return self._apply(op, params, plan)
        except (OperationError, SetupError) as exc:
            return {"ok": False, "error": {"code": exc.code, "message": _masked(exc.message)}}

    def start_setup(self, payload):
        return setup_start(self.state, payload)

    def stop_setup(self, reason="service"):
        return setup_stop(self.state, reason)

    def expire_setup(self):
        return setup_expire(self.state)

    def _plan(self, op, params):
        if op in {"service_restart_graceful", "service_restart", "service_stop"}:
            service = _service(params)
            action = "restart" if "restart" in op else "stop"
            return {"op": op, "action": action, "service": service, "changes": [f"systemctl {action} {service}"]}
        if op == "nginx_reload":
            return {"op": op, "changes": ["nginx -t", "systemctl reload nginx"]}
        if op in {"cache_clear", "cache_clear_force"}:
            name = str(params.get("service") or "nginx").lower()
            if name not in CACHE_PATHS:
                raise OperationError("invalid_cache_path", "Кэш не входит в allowlist")
            return {"op": op, "path": str(CACHE_PATHS[name]), "changes": ["Удалить содержимое известного кэш-каталога"]}
        if op == "tmp_clean":
            return {"op": op, "path": str(self.state.directory / "tmp"), "changes": ["Удалить временные файлы агента"]}
        if op == "cert_renew_dry":
            return {"op": op, "changes": ["certbot renew --dry-run"], "mutates": False}
        if op in {"apt_update", "dnf_update"}:
            manager = "apt-get" if op == "apt_update" else "dnf"
            return {"op": op, "manager": manager, "changes": [f"{manager} update"]}
        if op in {"package_install", "package_remove"}:
            packages = _packages(params)
            action = "install" if op == "package_install" else "remove"
            return {"op": op, "packages": packages, "action": action,
                    "changes": [f"Менеджер пакетов выполнит {action}"]}
        if op == "packages_installed":
            return {"op": op, "changes": []}
        if op == "config_read":
            path = _read_path_in_roots(params.get("path"))
            if not path.is_file():
                raise OperationError("config_not_found", "Файл конфигурации не найден")
            return {"op": op, "path": str(path), "changes": []}
        if op in {"db_list", "db_status"}:
            engine = str(params.get("engine") or "").lower()
            if engine and engine not in {"mysql", "postgres", "postgresql"}:
                raise OperationError("invalid_database_engine", "Поддерживаются mysql и postgres")
            return {"op": op, "engine": engine or "all", "changes": []}
        if op == "db_backup":
            engine = str(params.get("engine") or "").lower()
            if engine not in {"mysql", "postgres", "postgresql"}:
                raise OperationError("invalid_database_engine", "Для backup укажите mysql или postgres")
            database = _database(params.get("database"))
            target = Path(str(params.get("path") or (self.state.directory / "backups" / (database + ".dump")))).expanduser().resolve()
            backup_root = (self.state.directory / "backups").resolve()
            if target != backup_root and backup_root not in target.parents:
                raise OperationError("invalid_backup_path", "Backup должен сохраняться только в state/backups")
            return {"op": op, "engine": engine, "database": database, "path": str(target),
                    "changes": ["Создать backup базы данных"]}
        if op == "git_pull":
            path = _repo_path(params.get("path"))
            return {"op": op, "path": str(path), "changes": ["git pull --ff-only"]}
        if op == "systemd_reload":
            return {"op": op, "changes": ["systemctl daemon-reload"]}
        if op == "cert_renew":
            return {"op": op, "changes": ["certbot renew"]}
        if op == "shell":
            command = str(params.get("command") or "").strip()
            if not command or len(command) > 2000 or "\x00" in command:
                raise OperationError("invalid_shell_command", "Команда должна быть непустой и не длиннее 2000 символов")
            return {"op": op, "command": _masked(command), "dangerous": bool(DANGEROUS_SHELL.search(command)),
                    "changes": ["Выполнить shell-команду от root"]}
        if op == "config_apply":
            path = _path_in_roots(params.get("path"))
            content = params.get("content")
            if not isinstance(content, str) or len(content.encode("utf-8")) > 65536:
                raise OperationError("invalid_config", "Конфигурация должна быть текстом до 64 KiB")
            return {"op": op, "path": str(path), "bytes": len(content.encode("utf-8")), "changes": ["Создать backup и заменить конфигурацию"]}
        if op == "backup_cleanup":
            days = int(params.get("older_than_days", 30))
            if days < 1 or days > 3650:
                raise OperationError("invalid_retention", "Срок хранения от 1 до 3650 дней")
            return {"op": op, "path": str(self.rollback_dir), "older_than_days": days, "changes": ["Удалить старые rollback backup"]}
        if op == "logs_tail":
            service = _service(params)
            lines = max(1, min(int(params.get("lines", 50)), 50))
            return {"op": op, "service": service, "lines": lines, "changes": []}
        if op == "status":
            return {"op": op, "changes": []}
        if op == "disk":
            return {"op": op, "changes": []}
        if op == "services":
            return {"op": op, "changes": []}
        if op == "ports":
            return {"op": op, "changes": []}
        if op == "certs":
            return {"op": op, "changes": []}
        raise OperationError("unknown_operation", "Операция не зарегистрирована")

    def _apply(self, op, params, plan):
        if op == "status":
            return {"ok": True, "data": collect_profile()}
        if op == "disk":
            profile = collect_profile()
            return {"ok": True, "data": {"disks": profile.get("disks", [])}}
        if op == "services":
            profile = collect_profile()
            return {"ok": True, "data": {"services": profile.get("services", {})}}
        if op == "ports":
            return {"ok": True, "data": {"ports": _listeners()}}
        if op == "certs":
            return {"ok": True, "data": {"certs": [{"domain": domain, "days_left": _certificate_days(domain)} for domain in _domains()]}}
        if op == "logs_tail":
            result = _run("journalctl", "-u", plan["service"], "-n", str(plan["lines"]), "--no-pager")
            return {"ok": result.returncode == 0, "data": {"lines": _masked(result.stdout)}, "error": _masked(result.stderr) if result.returncode else None}
        if op == "service_restart_graceful":
            result = _run("systemctl", "reload-or-restart", plan["service"])
            return self._command_result(result)
        if op == "nginx_reload":
            check = _run("nginx", "-t")
            if check.returncode != 0:
                return {"ok": False, "error": {"code": "nginx_config_invalid", "message": _masked(check.stderr or check.stdout)}}
            return self._command_result(_run("systemctl", "reload", "nginx"))
        if op == "cert_renew_dry":
            return self._command_result(_run("certbot", "renew", "--dry-run", timeout=120))
        if op in {"apt_update", "dnf_update"}:
            return self._command_result(_run("apt-get", "update") if op == "apt_update" else _run("dnf", "check-update"))
        if op in {"package_install", "package_remove"}:
            manager = "apt-get" if shutil.which("apt-get") else "dnf"
            return self._command_result(_run(manager, plan["action"], "-y", *plan["packages"], timeout=300))
        if op == "packages_installed":
            if shutil.which("dpkg-query"):
                return self._command_result(_run("dpkg-query", "-W", "-f", "${binary:Package}\t${Version}\n"))
            return self._command_result(_run("rpm", "-qa"))
        if op == "config_read":
            try:
                return {"ok": True, "data": {"path": plan["path"], "content": _masked(Path(plan["path"]).read_text(encoding="utf-8"))}}
            except (OSError, UnicodeError) as exc:
                raise OperationError("config_read_failed", str(exc)) from exc
        if op == "db_list":
            engines = [plan["engine"]] if plan["engine"] != "all" else ["mysql", "postgres"]
            output = {}
            for engine in engines:
                command = ("mysql", "-NBe", "SHOW DATABASES") if engine == "mysql" else ("psql", "-At", "-c", "\\l")
                result = _run(*command)
                output[engine] = {"ok": result.returncode == 0, "output": _masked(result.stdout or result.stderr)}
            return {"ok": any(item["ok"] for item in output.values()), "data": output}
        if op == "db_status":
            engines = [plan["engine"]] if plan["engine"] != "all" else ["mysql", "postgres"]
            output = {}
            for engine in engines:
                executable = "mysqladmin" if engine == "mysql" else "pg_isready"
                result = _run(executable)
                output[engine] = {"ok": result.returncode == 0, "output": _masked(result.stdout or result.stderr)}
            return {"ok": all(item["ok"] for item in output.values()), "data": output}
        if op == "db_backup":
            Path(plan["path"]).parent.mkdir(parents=True, exist_ok=True)
            command = (("mysqldump", plan["database"]) if plan["engine"] == "mysql"
                       else ("pg_dump", "--format=custom", "--file", plan["path"], plan["database"]))
            if plan["engine"] == "mysql":
                result = _run(*command)
                if result.returncode == 0:
                    Path(plan["path"]).write_text(result.stdout, encoding="utf-8")
                return self._command_result(result)
            return self._command_result(_run(*command, timeout=300))
        if op == "git_pull":
            return self._command_result(_run("git", "-C", plan["path"], "pull", "--ff-only", timeout=300))
        if op == "systemd_reload":
            return self._command_result(_run("systemctl", "daemon-reload"))
        if op == "cert_renew":
            return self._command_result(_run("certbot", "renew", timeout=300))
        if op == "shell":
            return self._command_result(_run("sh", "-c", str(params["command"]), timeout=120))
        if op == "tmp_clean":
            path = self.state.directory / "tmp"
            path.mkdir(parents=True, exist_ok=True)
            for child in path.iterdir():
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
            return {"ok": True, "data": {"path": str(path)}}
        if op in {"cache_clear", "cache_clear_force"}:
            path = Path(plan["path"])
            removed = 0
            if path.is_dir():
                for child in path.iterdir():
                    if child.is_dir() and op == "cache_clear_force":
                        shutil.rmtree(child)
                        removed += 1
                    elif child.is_file():
                        child.unlink()
                        removed += 1
            return {"ok": True, "data": {"path": str(path), "removed": removed}}
        if op in {"service_restart", "service_stop"}:
            action = "restart" if op == "service_restart" else "stop"
            return self._command_result(_run("systemctl", action, plan["service"]))
        if op == "backup_cleanup":
            cutoff = time.time() - plan["older_than_days"] * 86400
            removed = 0
            for path in self.rollback_dir.glob("*.bak"):
                if path.is_file() and path.stat().st_mtime < cutoff:
                    path.unlink()
                    removed += 1
            return {"ok": True, "data": {"removed": removed}}
        if op == "config_apply":
            return self._apply_config(params, plan)
        raise OperationError("unknown_operation", "Операция не зарегистрирована")

    def _apply_config(self, params, plan):
        path = Path(plan["path"])
        backup = self.rollback_dir / (path.name + "." + str(int(time.time())) + ".bak")
        existed = path.exists()
        if existed:
            shutil.copy2(path, backup)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_suffix(path.suffix + ".siteadmin.tmp")
            temporary.write_text(params["content"], encoding="utf-8")
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
            nginx_roots = [root.resolve() for root in CONFIG_ROOTS if root.name == "nginx"]
            if any(path == root or root in path.parents for root in nginx_roots):
                verify = _run("nginx", "-t")
                if verify.returncode != 0:
                    raise OperationError("post_verify_failed", _masked(verify.stderr or verify.stdout))
            return {"ok": True, "data": {"path": str(path), "verified": True}, "rollback": {"backup": str(backup) if existed else None}}
        except (OSError, OperationError) as exc:
            if existed and backup.exists():
                shutil.copy2(backup, path)
            elif not existed:
                path.unlink(missing_ok=True)
            return {"ok": False, "error": {"code": getattr(exc, "code", "config_apply_failed"), "message": _masked(str(exc))}, "rollback": {"used": True, "backup": str(backup) if existed else None}}

    @staticmethod
    def _command_result(result):
        data = _masked((result.stdout or "").strip())
        error = _masked((result.stderr or "").strip())
        value = {"ok": result.returncode == 0, "data": {"output": data}}
        if result.returncode:
            value["error"] = {"code": "command_failed", "message": error or data}
        return value
