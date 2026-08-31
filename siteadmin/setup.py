"""Ограниченные setup-операции агента и локальное состояние setup mode."""

import datetime
import hashlib
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path


SETUP_CATALOG = {
    "setup_install_pkg": "Установка разрешённого пакета",
    "setup_nginx_site": "Создание nginx site-конфига",
    "setup_certbot_issue": "Выпуск сертификата certbot",
    "setup_ufw_rule": "Изменение правила ufw",
    "setup_fail2ban": "Настройка fail2ban",
    "setup_deploy": "Деплой сайта с backup",
    "setup_run_cmd": "Команда root в setup-сессии",
}
SETUP_PRIVILEGES = {"user_hosting", "root"}
SETUP_TIMERS = {30, 120, 480}
SETUP_PACKAGES = {"nginx", "certbot", "python3-certbot-nginx", "ufw", "fail2ban"}
SETUP_JAILS = {"sshd", "nginx-http-auth", "nginx-botsearch", "recidive"}
CONFIG_ROOTS = (Path("/etc/nginx/sites-available"),)
DEPLOY_SOURCE_ROOTS = (Path("/var/www"), Path("/srv/www"), Path("/home"))
DEPLOY_DEST_ROOTS = (Path("/var/www"), Path("/srv/www"))
BLOCKED_PATHS = tuple(Path(item) for item in (
    "/etc/passwd", "/etc/shadow", "/boot", "/dev", "/proc", "/sys", "/var/lib/siteadmin",
))
BLOCKED_COMMAND = re.compile(
    r"(?ix)(?:\brm\s+(?:-[\w-]+\s+)*-rf\s+(?:/(?:\s|$)|/etc/passwd(?:\s|$)|/etc/shadow(?:\s|$)|"
    r"/(?:boot|dev|proc|sys|var/lib/siteadmin)(?:/|\s|$))|\bmkfs(?:\.[\w]+)?\b|\bdd\s+if=|"
    r"\b(?:systemctl|service)\s+(?:stop|disable|mask)\s+(?:siteadmin(?:\.service)?|sshd|ssh|systemd)\b|"
    r"\b(?:shutdown|reboot|halt)\b)"
)
DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,80}$")
SECRET_RE = re.compile(r"(?i)(password|passwd|token|secret|private[_ -]?key|credential|api[_ -]?key)(\s*[:=]\s*)[^\s,;]+")


class SetupError(Exception):
    def __init__(self, code: str, message: str = ""):
        self.code = code
        self.message = message or code
        super().__init__(self.message)


def _masked(value: str) -> str:
    return SECRET_RE.sub(lambda match: match.group(1) + match.group(2) + "[redacted]", value)[:8000]


def _run(*args, timeout=120):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise SetupError("command_unavailable", str(exc)) from exc


def _inside(path: Path, roots) -> bool:
    return any(path == root or root in path.parents for root in (item.resolve() for item in roots))


def _blocked_path(path: Path) -> bool:
    return any(path == item or item in path.parents for item in BLOCKED_PATHS)


def _safe_path(value, roots, code="path_not_allowed") -> Path:
    path = Path(str(value or "")).expanduser().resolve()
    if _blocked_path(path) or not _inside(path, roots):
        raise SetupError(code, "Путь запрещён blocklist или не входит в allowlist")
    return path


def _domain(value: str) -> str:
    value = str(value or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(value) or ".." in value or "." not in value:
        raise SetupError("invalid_domain", "Домен не прошёл проверку")
    return value


def _setup_mode(state) -> dict | None:
    value = state.read().get("setup_mode")
    if not isinstance(value, dict):
        return None
    try:
        if float(value.get("expires_at", 0)) <= time.time():
            state.update(setup_mode=None)
            return None
    except (TypeError, ValueError):
        state.update(setup_mode=None)
        return None
    return value


def setup_status(state) -> dict:
    value = _setup_mode(state)
    return value or {"active": False}


def setup_start(state, payload: dict) -> dict:
    privilege = str(payload.get("privilege") or "")
    if privilege not in SETUP_PRIVILEGES:
        raise SetupError("invalid_privilege", "Уровень setup не разрешён")
    try:
        expires_at = datetime.datetime.fromisoformat(str(payload["expires_at"]).replace("Z", "+00:00")).timestamp()
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise SetupError("invalid_expiry", "Некорректный срок setup-сессии") from exc
    if expires_at <= time.time() or expires_at > time.time() + max(SETUP_TIMERS) * 60 + 30:
        raise SetupError("invalid_expiry", "Срок setup-сессии вне допустимого диапазона")
    value = {"active": True, "session_id": int(payload.get("session_id", 0)),
             "privilege": privilege, "expires_at": expires_at}
    state.update(setup_mode=value)
    return {"ok": True, "data": {"active": True, "privilege": privilege, "expires_at": expires_at}}


def setup_stop(state, reason="service") -> dict:
    was_active = _setup_mode(state) is not None
    state.update(setup_mode=None)
    return {"ok": True, "data": {"active": False, "reason": reason, "was_active": was_active}}


def setup_expire(state) -> bool:
    value = state.read().get("setup_mode")
    if isinstance(value, dict):
        try:
            if float(value.get("expires_at", 0)) <= time.time():
                state.update(setup_mode=None)
                return True
        except (TypeError, ValueError):
            state.update(setup_mode=None)
            return True
    return False


def setup_plan(op: str, params: dict, state) -> dict:
    mode = _setup_mode(state)
    if mode is None:
        raise SetupError("setup_required", "Setup mode не активен или истёк")
    if op == "setup_install_pkg":
        packages = params.get("packages", params.get("package"))
        packages = [packages] if isinstance(packages, str) else packages
        if not isinstance(packages, list) or not packages or len(packages) > 4 or any(item not in SETUP_PACKAGES for item in packages):
            raise SetupError("invalid_package", "Пакет не входит в allowlist")
        return {"op": op, "packages": packages, "changes": ["apt-get install разрешённых пакетов"]}
    if op == "setup_nginx_site":
        name = str(params.get("name") or "")
        content = params.get("content")
        if not NAME_RE.fullmatch(name) or not isinstance(content, str) or len(content.encode()) > 65536:
            raise SetupError("invalid_nginx_site", "Имя или конфигурация nginx некорректны")
        path = _safe_path(CONFIG_ROOTS[0] / name, CONFIG_ROOTS)
        return {"op": op, "path": str(path), "bytes": len(content.encode()), "changes": ["backup, nginx -t, reload"]}
    if op == "setup_certbot_issue":
        domains = params.get("domains", params.get("domain"))
        domains = [domains] if isinstance(domains, str) else domains
        if not isinstance(domains, list) or not 1 <= len(domains) <= 20:
            raise SetupError("invalid_domain", "Нужен список доменов")
        domains = [_domain(item) for item in domains]
        email = str(params.get("email") or "").strip()
        if "@" not in email or len(email) > 254:
            raise SetupError("invalid_email", "Нужен email для certbot")
        return {"op": op, "domains": domains, "changes": ["certbot --nginx для указанных доменов"]}
    if op == "setup_ufw_rule":
        action = str(params.get("action") or "").lower()
        protocol = str(params.get("protocol") or "tcp").lower()
        port = str(params.get("port") or "")
        if action not in {"allow", "deny"} or protocol not in {"tcp", "udp"} or not port.isdigit() or not 1 <= int(port) <= 65535:
            raise SetupError("invalid_ufw_rule", "Правило ufw некорректно")
        return {"op": op, "action": action, "port": int(port), "protocol": protocol, "changes": ["ufw обновит одно правило"]}
    if op == "setup_fail2ban":
        jail = str(params.get("jail") or "sshd")
        if jail not in SETUP_JAILS:
            raise SetupError("invalid_jail", "Jail не входит в allowlist")
        return {"op": op, "jail": jail, "changes": ["включить fail2ban и jail"]}
    if op == "setup_deploy":
        source = _safe_path(params.get("source"), DEPLOY_SOURCE_ROOTS, "invalid_deploy_source")
        destination = _safe_path(params.get("destination"), DEPLOY_DEST_ROOTS, "invalid_deploy_destination")
        if not source.exists() or source == destination or destination in source.parents:
            raise SetupError("invalid_deploy_path", "Источник или назначение деплоя некорректны")
        return {"op": op, "source": str(source), "destination": str(destination), "changes": ["backup и замена содержимого назначения"]}
    if op == "setup_run_cmd":
        if mode.get("privilege") != "root":
            raise SetupError("root_required", "setup_run_cmd доступна только в root-сессии")
        command = str(params.get("command") or "").strip()
        if not command or len(command) > 2000 or "\x00" in command or BLOCKED_COMMAND.search(command):
            raise SetupError("blocked_command", "Команда заблокирована политикой setup")
        return {"op": op, "command": _masked(command), "changes": ["выполнить команду в root setup-сессии"]}
    raise SetupError("unknown_setup_operation", "Setup-операция не зарегистрирована")


def _backup(path: Path, state) -> Path | None:
    if not path.exists():
        return None
    rollback = state.directory / "rollback"
    rollback.mkdir(parents=True, exist_ok=True)
    backup = rollback / (path.name + ".setup-" + str(time.time_ns()) + ".bak")
    if path.is_dir():
        shutil.copytree(path, backup)
    else:
        shutil.copy2(path, backup)
    os.chmod(backup, 0o600) if backup.is_file() else None
    return backup


def _restore(path: Path, backup: Path | None):
    if path.exists():
        shutil.rmtree(path) if path.is_dir() else path.unlink()
    if backup:
        shutil.copytree(backup, path) if backup.is_dir() else shutil.copy2(backup, path)


def _apply_deploy(source: Path, destination: Path, state):
    backup = _backup(destination, state)
    temporary = Path(tempfile.mkdtemp(prefix="siteadmin-deploy-", dir=state.directory))
    try:
        target = temporary / "payload"
        if source.is_dir():
            shutil.copytree(source, target)
        elif source.is_file() and source.suffix in {".tar", ".gz", ".tgz", ".bz2", ".xz"}:
            target.mkdir()
            with tarfile.open(source) as archive:
                for member in archive.getmembers():
                    member_path = (target / member.name).resolve()
                    if member_path != target.resolve() and target.resolve() not in member_path.parents:
                        raise SetupError("invalid_archive", "Архив содержит выход за пределы назначения")
                    if member.issym() or member.islnk() or _blocked_path(member_path):
                        raise SetupError("invalid_archive", "Архив содержит запрещённую ссылку или путь")
                archive.extractall(target)
        else:
            raise SetupError("invalid_deploy_source", "Поддерживается каталог или tar-архив")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            shutil.rmtree(destination) if destination.is_dir() else destination.unlink()
        shutil.move(str(target), str(destination))
        return backup
    except Exception:
        _restore(destination, backup)
        raise
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


def setup_apply(op: str, params: dict, plan: dict, state) -> dict:
    if op == "setup_install_pkg":
        return _command_result(_run("apt-get", "install", "-y", *plan["packages"]))
    if op == "setup_nginx_site":
        path = Path(plan["path"])
        backup = _backup(path, state)
        temporary = path.with_suffix(path.suffix + ".siteadmin.tmp")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary.write_text(params["content"], encoding="utf-8")
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
            verify = _run("nginx", "-t")
            if verify.returncode:
                raise SetupError("post_verify_failed", _masked(verify.stderr or verify.stdout))
            reload_result = _run("systemctl", "reload", "nginx")
            result = _command_result(reload_result)
            result["rollback"] = {"used": False, "backup": str(backup) if backup else None}
            return result
        except (OSError, SetupError) as exc:
            _restore(path, backup)
            return {"ok": False, "error": {"code": getattr(exc, "code", "setup_nginx_failed"), "message": _masked(str(exc))}, "rollback": {"used": True, "backup": str(backup) if backup else None}}
    if op == "setup_certbot_issue":
        args = ["certbot", "--nginx", "--non-interactive", "--agree-tos", "--keep-until-expiring", "--email", str(params["email"])]
        for domain in plan["domains"]:
            args.extend(("-d", domain))
        return _command_result(_run(*args, timeout=300))
    if op == "setup_ufw_rule":
        return _command_result(_run("ufw", plan["action"], f"{plan['port']}/{plan['protocol']}"))
    if op == "setup_fail2ban":
        enabled = _run("systemctl", "enable", "--now", "fail2ban")
        if enabled.returncode:
            return _command_result(enabled)
        return _command_result(_run("fail2ban-client", "set", plan["jail"], "start"))
    if op == "setup_deploy":
        try:
            backup = _apply_deploy(Path(plan["source"]), Path(plan["destination"]), state)
            return {"ok": True, "data": {"destination": plan["destination"]}, "rollback": {"used": False, "backup": str(backup) if backup else None}}
        except (OSError, SetupError) as exc:
            return {"ok": False, "error": {"code": getattr(exc, "code", "setup_deploy_failed"), "message": _masked(str(exc))}, "rollback": {"used": True}}
    if op == "setup_run_cmd":
        command = str(params.get("command") or "").strip()
        if not command or len(command) > 2000 or "\x00" in command or BLOCKED_COMMAND.search(command):
            raise SetupError("blocked_command", "Команда заблокирована политикой setup")
        result = _run("sh", "-c", command, timeout=120)
        return _command_result(result)
    raise SetupError("unknown_setup_operation", "Setup-операция не зарегистрирована")


def _command_result(result):
    output = _masked((result.stdout or "").strip())
    error = _masked((result.stderr or "").strip())
    value = {"ok": result.returncode == 0, "data": {"output": output}}
    if result.returncode:
        value["error"] = {"code": "command_failed", "message": error or output}
    return value
