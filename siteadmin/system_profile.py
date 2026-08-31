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


def collect() -> dict:
    disks = []
    for path in ("/", "/var", "/home"):
        try:
            usage = shutil.disk_usage(path)
            disks.append({"mount": path, "total_bytes": usage.total, "used_bytes": usage.used,
                          "used_percent": round(usage.used * 100 / usage.total, 1)})
        except OSError:
            pass
    services = {}
    for name in ("nginx", "apache2", "httpd", "php-fpm", "docker", "fail2ban"):
        if shutil.which("systemctl"):
            services[name] = _command("systemctl", "is-active", name) or "unknown"
        else:
            services[name] = "unknown"
    software = {name: bool(shutil.which(name)) for name in ("nginx", "apache2", "httpd", "php", "node", "docker", "podman")}
    return {"os": _os_release(), "kernel": platform.release(), "architecture": platform.machine(),
            "hostname": socket.gethostname()[:255], "uptime_seconds": _uptime(),
            "cpu": {"model": _cpu_model(), "cores": os.cpu_count() or 1}, "memory": _memory(),
            "disks": disks, "python": platform.python_version(), "software": software,
            "services": services, "network": {"interfaces": [name for _, name in socket.if_nameindex()]}}


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
