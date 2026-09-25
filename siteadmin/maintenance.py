"""Bounded, repeatable disk maintenance for the siteadmin agent."""

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


DOCKER_LOG_ROOT = Path("/var/lib/docker/containers")
BTMP_PATH = Path("/var/log/btmp")


@dataclass(frozen=True)
class CleanupSettings:
    journal_cap_mb: int = 100
    docker_log_cap_mb: int = 50
    btmp_cap_mb: int = 20

    @classmethod
    def from_env(cls):
        def integer(name, default, minimum=1):
            try:
                return max(minimum, int(os.environ.get(name, str(default))))
            except (TypeError, ValueError):
                return default

        return cls(
            journal_cap_mb=integer("JOURNAL_CAP_MB", 100),
            docker_log_cap_mb=integer("DOCKER_LOG_CAP_MB", 50),
            btmp_cap_mb=integer("BTMP_CAP_MB", 20),
        )


def _disk_usage():
    usage = shutil.disk_usage("/")
    total = int(usage.total)
    free = int(usage.free)
    used = max(0, total - free)
    return {
        "mount": "/",
        "total_bytes": total,
        "used_bytes": used,
        "available_bytes": free,
        "used_percent": round(used * 100 / total, 1) if total else 0,
    }


def _action(action_id, title, detail="", *, ok=True, freed_bytes=0):
    return {
        "id": action_id,
        "title": title,
        "ok": bool(ok),
        "freed_bytes": max(0, int(freed_bytes or 0)),
        "detail": str(detail or ""),
    }


def _files_over(path, limit):
    try:
        if not path.is_dir():
            return []
    except OSError:
        return []
    result = []
    for item in path.glob("*/*-json.log"):
        try:
            size = item.stat().st_size
        except OSError:
            continue
        if size > limit and item.is_file():
            result.append((item, size))
    return result


def _available_tools():
    tools = {}
    for name in ("journalctl", "apt-get", "dnf", "docker"):
        tools[name] = shutil.which(name)
    return tools


def plan_cleanup(*, deep=False, settings=None):
    """Return a non-mutating description of the cleanup actions."""
    settings = settings or CleanupSettings.from_env()
    tools = _available_tools()
    actions = []
    skipped = []

    if tools["journalctl"]:
        actions.append(_action("journal", "Сжать systemd journal", "dry-run: journalctl vacuum-size"))
    else:
        skipped.append({"id": "journal", "reason": "journalctl не установлен"})

    if tools["apt-get"]:
        actions.append(_action("package_cache", "Очистить кэш apt", "dry-run: apt-get clean"))
    elif tools["dnf"]:
        actions.append(_action("package_cache", "Очистить кэш dnf", "dry-run: dnf clean all"))
    else:
        skipped.append({"id": "package_cache", "reason": "apt-get и dnf не установлены"})

    if tools["docker"]:
        actions.extend([
            _action("docker_dangling", "Удалить dangling-образы Docker", "dry-run: docker image prune -f"),
            _action("docker_builder", "Очистить кэш сборки Docker", "dry-run: docker builder prune -f"),
        ])
        if deep:
            actions.append(_action("docker_unused", "Удалить неиспользуемые образы Docker", "dry-run: docker image prune -a -f"))
    else:
        skipped.append({"id": "docker", "reason": "docker не установлен"})

    log_files = _files_over(DOCKER_LOG_ROOT, settings.docker_log_cap_mb * 1024 * 1024)
    actions.append(_action(
        "docker_logs", "Обрезать большие Docker-логи",
        "dry-run: %d json-file логов" % len(log_files),
    ))
    try:
        btmp_size = BTMP_PATH.stat().st_size
    except OSError:
        btmp_size = 0
    actions.append(_action(
        "btmp", "Обрезать btmp",
        "dry-run: %d байт" % btmp_size if btmp_size > settings.btmp_cap_mb * 1024 * 1024 else "порог не достигнут",
    ))
    if not actions:
        skipped.append({"id": "cleanup", "reason": "нет доступных безопасных действий"})
    return {"actions": actions, "skipped": skipped, "deep": bool(deep)}


def _run(command):
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(command, 1, "", str(exc))


def _command_action(action_id, title, command):
    before = _disk_usage()
    result = _run(command)
    after = _disk_usage()
    detail = (result.stdout or result.stderr or "").strip()[:1000]
    return _action(action_id, title, detail, ok=result.returncode == 0,
                   freed_bytes=max(0, after["available_bytes"] - before["available_bytes"]))


def run_cleanup(*, deep=False, dry_run=False, settings=None):
    """Run the bounded cleanup and return the stable report contract."""
    started = time.monotonic()
    settings = settings or CleanupSettings.from_env()
    before_df = _disk_usage()
    plan = plan_cleanup(deep=deep, settings=settings)
    if dry_run:
        return {
            "actions": plan["actions"], "freed_total": 0, "df_before": before_df,
            "df_after": before_df, "duration_ms": int((time.monotonic() - started) * 1000),
            "skipped": plan["skipped"],
        }

    tools = _available_tools()
    actions = []
    if tools["journalctl"]:
        actions.append(_command_action(
            "journal", "Сжать systemd journal",
            [tools["journalctl"], "--vacuum-size=%dM" % settings.journal_cap_mb],
        ))
    if tools["apt-get"]:
        actions.append(_command_action("package_cache", "Очистить кэш apt", [tools["apt-get"], "clean"]))
    elif tools["dnf"]:
        actions.append(_command_action("package_cache", "Очистить кэш dnf", [tools["dnf"], "clean", "all"]))
    if tools["docker"]:
        actions.append(_command_action("docker_dangling", "Удалить dangling-образы Docker",
                                       [tools["docker"], "image", "prune", "-f"]))
        actions.append(_command_action("docker_builder", "Очистить кэш сборки Docker",
                                       [tools["docker"], "builder", "prune", "-f"]))
        if deep:
            actions.append(_command_action("docker_unused", "Удалить неиспользуемые образы Docker",
                                           [tools["docker"], "image", "prune", "-a", "-f"]))

    log_limit = settings.docker_log_cap_mb * 1024 * 1024
    for path, size in _files_over(DOCKER_LOG_ROOT, log_limit):
        try:
            with path.open("r+b") as stream:
                stream.truncate(0)
            actions.append(_action("docker_log:%s" % path.parent.name, "Обрезать Docker-лог",
                                   str(path), freed_bytes=size))
        except OSError as exc:
            actions.append(_action("docker_log:%s" % path.parent.name, "Обрезать Docker-лог",
                                   str(exc), ok=False))

    try:
        btmp_size = BTMP_PATH.stat().st_size
    except OSError:
        btmp_size = 0
    if btmp_size > settings.btmp_cap_mb * 1024 * 1024:
        try:
            with BTMP_PATH.open("r+b") as stream:
                stream.truncate(0)
            actions.append(_action("btmp", "Обрезать btmp", str(BTMP_PATH), freed_bytes=btmp_size))
        except OSError as exc:
            actions.append(_action("btmp", "Обрезать btmp", str(exc), ok=False))

    after_df = _disk_usage()
    freed_total = sum(item["freed_bytes"] for item in actions)
    return {
        "actions": actions, "freed_total": freed_total, "df_before": before_df,
        "df_after": after_df, "duration_ms": int((time.monotonic() - started) * 1000),
        "skipped": plan["skipped"],
    }