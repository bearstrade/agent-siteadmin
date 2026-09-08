"""Сбор обработанного системного профиля Linux."""

import os
import platform
import shutil
import socket
import subprocess
import sys
from pathlib import Path


def _command(*args, timeout=3):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _os_release():
    values = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            values[key] = value.strip('"')
    except OSError:
        pass
    return {key: values.get(key) for key in ("ID", "VERSION_ID", "PRETTY_NAME")}


def _memory():
    values = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, _, value = line.partition(":")
            values[key] = int(value.strip().split()[0]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", values.get("MemFree", 0))
    return {"total_bytes": total, "available_bytes": available, "used_percent": round((1 - available / total) * 100, 1) if total else None}


def _hermes_detected() -> bool:
    """True, если на хосте работает Hermes (uHive): docker-контейнер, systemd-юнит
    или процесс, в имени/образе/аргументах которых есть 'hermes'."""
    if shutil.which("docker"):
        out = _command("docker", "ps", "--format", "{{.Names}}\t{{.Image}}", timeout=4)
        if "hermes" in (out or "").lower():
            return True
    units = _command("systemctl", "list-units", "--type=service", "--no-legend", "--no-pager", timeout=4)
    if "hermes" in (units or "").lower():
        return True
    procs = _command("ps", "-eo", "args", timeout=4)
    return "hermes" in (procs or "").lower()


def collect() -> dict:
    disks = []
    for path in ("/", "/var", "/home"):
        try:
            usage = shutil.disk_usage(path)
            disk = {"mount": path, "total_bytes": usage.total, "used_bytes": usage.used,
                    "used_percent": round(usage.used * 100 / usage.total, 1)}
            if path == "/":
                # Топ-каталоги по размеру — только для корневого раздела (du -x).
                disk["top_consumers"] = _disk_top_consumers()
            disks.append(disk)
        except OSError:
            pass
    services = {}
    for name in ("nginx", "apache2", "httpd", "php-fpm", "docker", "fail2ban"):
        if shutil.which("systemctl"):
            services[name] = _command("systemctl", "is-active", name) or "unknown"
        else:
            services[name] = "unknown"
    software = {name: bool(shutil.which(name)) for name in ("nginx", "apache2", "httpd", "php", "node", "docker", "podman")}
    software["hermes"] = _hermes_detected()
    cpu = {"model": _cpu_model(), "cores": os.cpu_count() or 1}
    load = _loadavg()
    if load:
        cpu["load"] = load
    memory = _memory()
    swap = _swap()
    if swap:
        memory["swap"] = swap
    profile = {"os": _os_release(), "kernel": platform.release(), "architecture": platform.machine(),
               "hostname": socket.gethostname()[:255], "uptime_seconds": _uptime(),
               "cpu": cpu, "memory": memory,
               "disks": disks, "python": platform.python_version(), "software": software,
               "services": services, "network": {"interfaces": [name for _, name in socket.if_nameindex()]}}
    processes = _top_processes()
    if processes:
        profile["processes"] = processes
    return profile


def _loadavg() -> list:
    """Load average 1/5/15 из /proc/loadavg; [] если недоступно."""
    try:
        parts = Path("/proc/loadavg").read_text().split()
        return [round(float(parts[0]), 2), round(float(parts[1]), 2), round(float(parts[2]), 2)]
    except (OSError, ValueError, IndexError):
        return []


def _swap() -> dict:
    """Swap из /proc/meminfo; None если swap отсутствует или не читается."""
    try:
        values = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, _, value = line.partition(":")
            values[key] = int(value.strip().split()[0]) * 1024
        total = values.get("SwapTotal", 0)
        free = values.get("SwapFree", 0)
        if not total:
            return None
        used = max(0, total - free)
        return {"total_bytes": total, "used_bytes": used,
                "used_percent": round(used * 100 / total, 1)}
    except (OSError, ValueError, IndexError):
        return None


def _top_processes(limit: int = 6) -> list:
    """Топ процессов по памяти: pid, имя, %MEM, RSS в байтах."""
    out = _command("ps", "-eo", "pid=,comm=,%mem=,rss=", "--sort=-%mem", timeout=4)
    rows = []
    for line in (out or "").splitlines():
        parts = line.split(None, 3)
        if len(parts) < 4:
            continue
        pid, name, mem, rss = parts
        rows.append({
            "pid": int(pid) if pid.lstrip("-").isdigit() else None,
            "name": name[:64],
            "command": name[:128],
            "mem_percent": _to_float(mem),
            "rss_bytes": int(float(rss or 0) * 1024),
        })
        if len(rows) >= limit:
            break
    return rows


def _disk_top_consumers(limit: int = 4) -> list:
    """Крупнейшие каталоги на «/» (du -x — не пересекает ФС; /proc,/sys,/dev отпадают)."""
    out = _command("du", "-x", "-k", "--max-depth=1", "/", timeout=12)
    rows = []
    for line in (out or "").splitlines():
        kb, _, path = line.rstrip("\n").partition("\t")
        if not kb.isdigit():
            continue
        path = path.rstrip("/") or "/"
        if path == "/":
            continue
        rows.append({"path": path[:255], "bytes": int(kb) * 1024})
    rows.sort(key=lambda r: r["bytes"], reverse=True)
    return rows[:limit]


def _to_float(value) -> float:
    try:
        return round(float(value), 1)
    except (TypeError, ValueError):
        return 0.0


def _uptime():
    try:
        return round(float(Path("/proc/uptime").read_text().split()[0]))
    except (OSError, ValueError, IndexError):
        return None


def _cpu_model():
    try:
        for line in Path("/proc/cpuinfo").read_text(errors="replace").splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()[:255]
    except OSError:
        pass
    return platform.processor()[:255]
