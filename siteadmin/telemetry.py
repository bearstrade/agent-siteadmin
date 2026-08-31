"""Пять минут агрегированной телеметрии без сырых логов."""

import os
import ssl
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib import parse, request

from .system_profile import _memory


def _cpu_sample():
    try:
        values = Path("/proc/loadavg").read_text().split()
        return round(float(values[0]) * 100 / max(os.cpu_count() or 1, 1), 1)
    except (OSError, ValueError, IndexError):
        return None


def _processes():
    rows = []
    for directory in Path("/proc").glob("[0-9]*"):
        try:
            name = (directory / "comm").read_text(errors="replace").strip()[:80]
            status = (directory / "status").read_text(errors="replace")
            memory = next((int(line.split()[1]) for line in status.splitlines() if line.startswith("VmRSS:")), 0)
            rows.append((memory, name))
        except (OSError, ValueError, IndexError):
            continue
    return [{"name": name, "memory_bytes": value} for value, name in sorted(rows, reverse=True)[:5]]


def _domains():
    domains = []
    for value in os.environ.get("SITEADMIN_DOMAINS", "").split(","):
        value = value.strip()
        if value:
            parsed = parse.urlparse(value if "://" in value else "https://" + value)
            if parsed.hostname and parsed.hostname not in domains:
                domains.append(parsed.hostname)
    return domains


def _certificate_days(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as connection:
            with context.wrap_socket(connection, server_hostname=domain) as secure:
                certificate = secure.getpeercert()
        expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(certificate["notAfter"]), timezone.utc)
        return (expiry - datetime.now(timezone.utc)).days
    except (OSError, KeyError, ValueError, ssl.SSLError):
        return None


def _reachability(domain):
    try:
        with request.urlopen("https://" + domain, timeout=3) as response:
            return 200 <= response.status < 500
    except (OSError, ValueError):
        return False


def collect(previous=None):
    memory = _memory()
    disks = []
    try:
        for line in Path("/proc/mounts").read_text().splitlines():
            mount = line.split()[1]
            if mount in {"/", "/var", "/home"} and not any(item["mount"] == mount for item in disks):
                stat = os.statvfs(mount)
                total = stat.f_blocks * stat.f_frsize
                available = stat.f_bavail * stat.f_frsize
                disks.append({"mount": mount, "used_percent": round((1 - available / total) * 100, 1) if total else 0})
    except (OSError, ValueError, IndexError):
        pass
    services = {}
    if shutil.which("systemctl"):
        for name in ("nginx", "apache2", "httpd", "docker", "fail2ban"):
            try:
                result = subprocess.run(("systemctl", "is-active", name), capture_output=True, text=True, timeout=2, check=False)
                services[name] = result.stdout.strip() or "unknown"
            except (OSError, subprocess.SubprocessError):
                services[name] = "unknown"
    domains = _domains()
    certs = [{"domain": domain, "days_left": _certificate_days(domain)} for domain in domains]
    reachability = [{"domain": domain, "reachable": _reachability(domain)} for domain in domains]
    return {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "cpu": {"avg_percent": _cpu_sample(), "max_percent": _cpu_sample()},
            "memory": memory, "disks": disks, "top_processes": _processes(),
            "services": services, "ports": (previous or {}).get("ports", []),
            "certs": certs, "reachability": reachability}
